#include  "helper.hpp"

bool running = true;
int client_socket = 0;
pthread_t t_send, t_recv, t_hrt;
char pubkey[1024];
u_char *publicKey, *privateKey;
#ifdef CRYPTO
RSA* s2c_pubkey;
#endif

void term()
{
    /* running = false;
    send(client_socket, "#!CLOSE", 7, 0);
    close(client_socket);
    pthread_detach(t_recv); pthread_detach(t_send);
    exit(0); */
    running = false;
    packet p;
    strncpy(p.type, "CLS", 3);
    strncpy(p.data, "DISCONNECTED", MAX_LEN);
    char* s = p.serialize();
    u_char* enc = Encrypt((const u_char*)s, s2c_pubkey);
    send(client_socket, enc, sizeof(packet), 0);
    pthread_detach(t_recv); pthread_detach(t_send);
    putc('\r', stdin);
    exit(0);
}

void* rcv(void* arg);
void* snd(void* arg);
void* hrt(void* arg);

int main()
{
    #ifndef CRYPTO
    fprintf(stderr, "CLIENT IS RUNNING WITHOUT ENCRYPTION!\nTo connect with server(s) that use encryption, use client that supports it!\n");
    #endif
    signal(SIGINT, (sighandler_t)term);
    printf("Enter server ip and port (default is 127.0.0.1:5524): ");
    std::string addr = "";
    std::getline(std::cin, addr);
    if (addr.empty())
        addr = "127.0.0.1:5524";
    char ip[16] = {0};
    int port = 0;
    if (sscanf(addr.c_str(), "%15[^:]:%d", ip, &port) != 2) 
    {
        fprintf(stderr, "Invalid input format\n");
        return 1;
    }

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        term();
    }
    sockaddr_in server_addr = {0};
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    #ifdef CRYPTO
    // generate public and private key
    
    GenerateKeyPair(&privateKey, &publicKey);
    #endif
    if (connect(client_socket, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
    {
        perror("connect");
        term();
    }

    // send server info
    const char* id    = cpu_uuid();
    const char* uid   = gen_uid();
    send(client_socket, id, 1024, 0);
    // msleep(10); // if something brakes uncomment this
    send(client_socket, uid, 1024, 0);
    #ifdef CRYPTO
    recv(client_socket, pubkey, 1024, 0);
    // send client's public key so we can encrypt the message later
    send(client_socket, publicKey, 1024, 0);
    // printf("%s\n", pubkey);
    s2c_pubkey = LoadPublicKeyFromString(pubkey);
    #endif
    printf("Welcome to the chat room (%s:%d)\nYour unique ID is: %s\n", ip, port, uid);
    pthread_create(&t_recv, 0, rcv, 0);
    pthread_create(&t_send, 0, snd, 0);
    pthread_create(&t_hrt, 0, hrt, 0);
    pthread_join(t_recv, 0);
    pthread_join(t_send, 0);
    pthread_join(t_hrt, 0);
}

void *hrt(void*)
{
    packet p("HRT");
    
    #ifdef CRYPTO
    RSA* pkey = LoadPublicKeyFromString(pubkey);
    #endif
    while (1)
    {
        #ifdef CRYPTO
        int t = time(0);
        std::string str_time = std::to_string(t);
        strncpy(p.data, str_time.c_str(), sizeof(p.data));
        const char* data = p.serialize();
        const unsigned char* enc = Encrypt((const u_char*)data, pkey);
        if (send(client_socket, enc, sizeof(packet), 0) == -1)
        {
            perror("send");
            term();
        }
        #else
        int t = time(0);
        std::string str_time = std::to_string(t);
        strncpy(p.data, str_time.c_str(), sizeof(p.data));
        const char* data = p.serialize();
        if (send(client_socket, data, sizeof(packet), 0) == -1)
        {
            perror("send");
            term();
        }
        #endif
        sleep(2);
    }
    
}

void *rcv(void *arg)
{
    #ifdef CRYPTO
    RSA* privkey = LoadPrivateKeyFromString((const char*)privateKey);
    #endif
    char *buff = new char[MAX_LEN];
    while (running)
    {
        int bytes = recv(client_socket, buff, MAX_LEN, 0);
        if (bytes <= 0)
            continue;
        else
        {
            packet *p = new packet;
            #ifdef CRYPTO
            u_char* decrypted = Decrypt((const u_char*)buff, privkey);
            p->deserialize((const char*)decrypted);
            printf("%s\n", p->data);
            #else
            memcpy(&p, buff, sizeof(packet));
            printf("%s\n", p->data);
            #endif
        }
        memset(buff, 0, MAX_LEN);
    }
    
    return nullptr;
}

void *snd(void *arg)
{
    #ifdef CRYPTO
    RSA* pkey = LoadPublicKeyFromString(pubkey);
    #endif
    std::string msg;
    
    while (running)
    {
        packet *p = new packet;
        if (std::cin.eof())
            term();
        std::getline(std::cin, msg);
        #ifdef CRYPTO
        strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
        strncpy(p->type, "MSG", 4);
        char* out = p->serialize();
        u_char* buffer = Encrypt((const unsigned char*)out, pkey);
        if (send(client_socket, buffer, sizeof(packet), 0) == -1)
        {
            perror("send");
            term();
        }
        #else
        strncpy(p->type, "MSG", sizeof(p->type));
        strncpy(p->data, msg.c_str(), MAX_INPUT);
        //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
        if (send(client_socket, p, MAX_LEN, 0) == -1)
        {
            perror("send");
            term();
        }
        #endif
        delete p;
    }
    
    return nullptr;
}
