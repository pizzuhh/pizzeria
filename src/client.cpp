#include  "helper.hpp"
#include <libnotify/notify.h>

/*Is client running?*/
bool running = true, connected = false;
/*client socket FD*/
int client_socket = 0;
/*Threads*/
pthread_t t_send, t_recv;
/*public key in plaintext*/
#ifdef CRYPTO
// server public key
char pubkey[1024];
/*The public private key pair*/
u_char *publicKey, *privateKey;

RSA* c2s_pubkey;
#endif

void term(bool ab = false, const char* message = "")
{
    /* running = false;
    send(client_socket, "#!CLOSE", 7, 0);
    close(client_socket);
    pthread_detach(t_recv); pthread_detach(t_send);
    exit(0); */
    if (connected)
    {
        running = false; // disable the client
        packet p; // packet
        strncpy(p.type, "CLS", 3); // set the packet type to "CLS" -> CLOSE
        strncpy(p.data, "DISCONNECTED", MAX_LEN); // set p.data
        char* s = p.serialize(); // turn the packet to string
        #ifdef CRYPTO // for encryption support
        u_char* enc = Encrypt((const u_char*)s, c2s_pubkey); // encrypt the string
        send(client_socket, enc, sizeof(packet), 0);
        #else 
        send(client_socket, s, sizeof(packet), 0);
        #endif
        // detach the threads
        pthread_detach(t_recv); pthread_detach(t_send);
    }
    notify_uninit();
    // exit
    if (ab)
    {
        // fprintf(stderr, message);
        abort();
    }
    else
        exit(0);
}
/*function to recive message from the server*/
void* rcv(void* arg);
/*function to send message to the server*/
void* snd(void* arg);
/*heart beat function. Sends a HRT packet to the server to verify if the client is valid.*/
void* ping(void* arg);



/*Main function:
 * generates key pairs
 * connects to server
 * sends required data
 */
int main()
{
    notify_init("pizzeria - client");
    #ifndef CRYPTO
    fprintf(stderr, "CLIENT IS RUNNING WITHOUT ENCRYPTION!\nTo connect with server(s) that use encryption, use client that supports it!\n");
    #endif
    signal(SIGINT, (sighandler_t)term);
    signal(SIGKILL, (sighandler_t)term);
    signal(SIGTERM, (sighandler_t)term);
    printf("Enter server ip and port (default is 127.0.0.1:5524): ");
    std::string addr = "";
    std::getline(std::cin, addr);
    if (addr.empty())
        addr = "127.0.0.1:5524";
    char ip[MAX_INPUT+1] = {0};
    int port = 0;
    if (sscanf(addr.c_str(), "%255[^:]:%d", ip, &port) != 2) 
    {
        fprintf(stderr, "Invalid input format\n");
        term(true);
    }

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        term(true);
    }
    sockaddr_in server_addr = {0};
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    //server_addr.sin_addr.s_addr = inet_addr(ip);
    if (inet_pton(AF_INET, toIPv4(ip), &server_addr.sin_addr.s_addr) <= 0)
    {
        perror("inet_pton");
        term(true);

    }
    #ifdef CRYPTO
    // generate public and private key
    
    GenerateKeyPair(&privateKey, &publicKey);
    #endif
    if (connect(client_socket, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
    {
        perror("connect");
        term(true);
    }
    
    // send server info
    const char* id    = get_hw_uuid();
    //const char* uid   = gen_uid();
    char *username = new char[MAX_INPUT];
    while (1)
    {
        printf("Enter username: ");
        fflush(stdout);

        fgets(username, MAX_INPUT, stdin);
        size_t len = strlen(username);
        username[len-1] = '\0';
        if (len == 0 || iswhitespace(username))
            fprintf(stderr, "Invalid username please try again!\n");
        else
        {
            for (int i = 0; i < strlen(username); i++)
                if (username[i] == ' ') username[i] = '-';
            break;
        }
    }

    send(client_socket, id, 1024, 0);
    delete[] id;
    // msleep(10); // if something brakes uncomment this
    send(client_socket, username, MAX_INPUT, 0);
    
    #ifdef CRYPTO
    // receive server's public key
    recv(client_socket, pubkey, 1024, 0);
    // send client's public key so we can encrypt the message later
    send(client_socket, publicKey, 1024, 0);
    // printf("%s\n", pubkey);
    c2s_pubkey = LoadPublicKeyFromString(pubkey);
    #endif
    printf("Welcome to the chat room (%s:%d)\n", ip, port);
    delete[] username;
    connected = true;
    pthread_create(&t_recv, 0, rcv, 0);
    pthread_create(&t_send, 0, snd, 0);
    pthread_join(t_recv, 0);
    pthread_join(t_send, 0);
}

void *rcv(void *arg)
{
    #ifdef CRYPTO
    RSA* privkey = LoadPrivateKeyFromString((const char*)privateKey);
    #endif
    char *buff = new char[sizeof(packet)];
    while (running)
    {
        int bytes = recv(client_socket, buff, sizeof(packet), 0);
        if (bytes <= 0)
            continue;
        else
        {
            packet *p = new packet;
            #ifdef CRYPTO
            u_char* decrypted = Decrypt((const u_char*)buff, privkey);
            p->deserialize((const char*)decrypted);
            if (!strncmp(p->type, "MSG", 4))
            {
                printf("%s\n", p->data);
            }
            else if (!strncmp(p->type, "PVM", 4))
            {
                
                NotifyNotification *notification = notify_notification_new("Private Message", p->data, NULL);
                notify_notification_set_timeout(notification, 4000);
                notify_notification_show(notification, NULL);
                printf("%s\n", p->data);
                g_object_unref(G_OBJECT(notification));
            }
            #else
            p->deserialize((const char*)buff);
            if (!strncmp(p->type, "MSG", 4))
            {
                printf("%s\n", p->data);
            }
            #endif
        }
        memset(buff, 0, MAX_LEN);
    }
    delete[] buff;
    return nullptr;
}
void send_message(std::string msg)
{
    packet *p = new packet;
    #ifdef CRYPTO
        strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
        strncpy(p->type, "MSG", 4);
        char* out = p->serialize();
        u_char* buffer = Encrypt((const unsigned char*)out, c2s_pubkey);
        if (send(client_socket, buffer, sizeof(packet), 0) == -1)
        {
            perror("send");
            term(true);
        }
        #else
        strncpy(p->type, "MSG", 4);
        strncpy(p->data, (char*)msg.c_str(), sizeof(packet));
        char *buffer_noenc = p->serialize();
        //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
        if (send(client_socket, buffer_noenc, sizeof(packet), 0) == -1)
        {
            perror("send");
            term(true);
        }
        #endif
        delete p;
}
void send_message_private(std::string msg)
{
    packet *p = new packet;
    #ifdef CRYPTO
        strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
        strncpy(p->type, "PVM", 4);
        char* out = p->serialize();
        u_char* buffer = Encrypt((const unsigned char*)out, c2s_pubkey);
        if (send(client_socket, buffer, sizeof(packet), 0) == -1)
        {
            perror("send");
            term(true);
        }
        #else
        strncpy(p->type, "PVM", 4);
        strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
        char *buffer_noenc = p->serialize();
        //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
        if (send(client_socket, buffer_noenc, sizeof(packet), 0) == -1)
        {
            perror("send");
            term(true);
        }
        #endif
        delete p;
}
void *snd(void *arg)
{
    std::string msg;
    
    while (running)
    {
        if (std::cin.eof())
            term();
        std::getline(std::cin, msg);
        if (msg.empty())
        {
            fprintf(stderr, "Do not send empty messages!\n");
            continue;
        }
        if (msg.substr(0, 2) != "#!") send_message(msg);
        else
        {
            msg.erase(0, 2);
            if (msg.substr(0, 2) == "pm")
            {
                msg.erase(0, 3);
                send_message_private(msg);
            }
        }
    }
    
    return nullptr;
}
