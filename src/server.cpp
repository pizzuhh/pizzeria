/*
server.cpp 

This file contains the code for the server side

*/

#include "helper.hpp"

using std::vector;
// sleep for miliseconds
#define msleep(ms) usleep(ms * 1000);
struct client
{
    int fd;
    // int id;
    char id[1024];
    char uid[1024];
    sockaddr addr;
    bool valid = true;
#ifdef CRYPTO
    char plainTextKey[1024];
    RSA *publicKey;
#endif
};

vector<client *> clients;

//client
void *handle_client(void *arg);
/*server admin client*/
void *server_client(void *arg);
// send message
void send_message(char *msg, char *sender);
void send_message(const char *msg);
void fsend_message(char *fmt, ...);
// handle broken pipe
void broken_pipe()
{
    for (client *cl : clients)
    {
        if (fcntl(cl->fd, F_GETFD) != -1 || errno == EBADF)
        {
            fprintf(stderr, "%s: Connection terminated!\n", cl->id);
            vector<client *>::iterator it = std::find(clients.begin(), clients.end(), cl);
            if (it != clients.end())
            {
                clients.erase(it);
            }
            delete cl;
        }
    }
    fprintf(stderr, "Broken pipe has been detected! (this shouldn't happen?) Could be that client has disconnected\n");
}

// handle segfault
void segfault_handler(int signo);
// handle server closing
void cls(int)
{
    send_message("Server has stopped");
    send_message("Do not send messages to this server");
    for (client* cl: clients)
    {
        delete cl;
    }
    printf("exited...\nyou can now press enter");
    exit(0);
}

// main function
int main(int argc, char **argv)
{
    // warn if the server is not running with encryption
    #ifndef CRYPTO
    fprintf(stderr, "SERVER IS RUNNING WITHOUT ENCRYPTION!\nTO USE ENCRYPTION REBUILD THE SERVER AND THE CLIENT!\n");
    #endif
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    signal(SIGINT, (sighandler_t)cls);
    int port = 0;
    if (strcmp(argv[1], "--default"))
    {
        printf("Enter port (the port must not be used by other process! Default port is 5524): ");
        char input[7];
        if (fgets(input, 6, stdin) != NULL)
        {
            // input[7] = '\0';
            if (input[0] == '\0')
                port = 5524;
            else
            {
                sscanf(input, "%d", &port);
            }
        }
        if (port == 0)
        {
            port = 5524;
        }
    }
    else 
    {
        port = 5524;  
    }
    /*
    following code creates a socket, binds to it and listens for connections
    */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(-1);
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (int *)1, sizeof(int));
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == -1)
    {
        perror("bind");
        exit(-1);
    }
    printf("Server listens on 127.0.0.1:%d\n", port);
    if (listen(fd, 5) == -1)
    {
        perror("listen");
        exit(-1);
    }
    int last_id = 0;
    sockaddr cl_addr;
    int socklen = sizeof(cl_addr);

#ifdef CRYPTO
    // generate private-public key pair
    GenerateKeyPair(&private_key_gen, &public_key_gen);
    s_pubkey = LoadPublicKeyFromString((const char*)public_key_gen);
    s_privkey = LoadPrivateKeyFromString((const char*)private_key_gen);
#endif
    pthread_t adminClient;
    pthread_create(&adminClient, 0, server_client, 0);
    while (true)
    {
        pthread_t p;
        int cl_fd = accept(fd, (sockaddr *)&cl_addr, (socklen_t *)&socklen);
        if (cl_fd > 0)
        {
            last_id++;
            client *cl = new client;
            cl->fd = cl_fd;
            cl->addr = cl_addr;
            // clients.push_back(cl);
            pthread_create(&p, 0, handle_client, (void *)cl);

            //            printf("Con: %d\n", clients.size());
        }
        else
            exit(-1);
    }
}

void *parse_command(const std::string command)
{
    printf("NOT IMPLEMENTED!\n");
    return 0;
}

void *server_client(void *arg)
{
    std::string buff;
    while (1)
    {

        printf("\nMessage: ");
        std::getline(std::cin, buff);
        if (buff.substr(0, 2) == "#!")
        {
            parse_command(buff.substr(2));
        }
        send_message(const_cast<char *>(buff.c_str()));
    }

    return nullptr;
}
void send_message(char *msg, char *sender)
{
    char *out = new char[1024];
    snprintf(out, 1024, "%s: %s", sender, msg);
    packet p;
    strncpy(p.data, "MSG", 4);
    strncpy(p.data, out, MAX_LEN);
    char* s = p.serialize();
    for (const auto &client : clients)
    {
        if (strcmp(client->uid, sender))
        {
#ifdef CRYPTO
            unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
            send(client->fd, encrypted, MAX_LEN, 0);
#else
            send(client->fd, s, strlen(out), 0);
#endif
        }
    }
    free(s);
    delete[] out;
}
void send_message(const char *msg)
{
    char *out = new char[1024];
    sprintf(out, "%s: %s", "[SERVER]", msg);
    packet p;
    strncpy(p.data, "MSG", 4);
    strncpy(p.data, out, MAX_LEN);
    char* s = p.serialize();
    for (const auto &client : clients)
    {   
#ifdef CRYPTO
        unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
        send(client->fd, encrypted, MAX_LEN, 0);
#else
        send(client->fd, s, strlen(out), 0);
#endif
    }
    free(s);
    delete[] out;
}
void fsend_message(const char *format, ...)
{
    char *out = new char[MAX_LEN];
    char *tmp = new char[MAX_LEN];

    va_list args;  // Define a variable argument list
    va_start(args, format);  // Initialize the argument list

    // Use vsnprintf to format the string with variable arguments
    vsnprintf(tmp, MAX_LEN, format, args);

    va_end(args);  // Clean up the argument list
    sprintf(out, "[SERVER]: %s", tmp);
    packet p("MSG", out);
    char *s = p.serialize();
    for (const auto &client : clients)
    {
#ifdef CRYPTO
        unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
        send(client->fd, encrypted, MAX_LEN, 0);
#else
        send(client->fd, s, strlen(s), 0);
#endif
    }
    free(s);
    delete[] out;  
    delete[] tmp;
}

void *handle_client(void *arg)
{
    // char msg[MAX_LEN] = {0};

    // get client info
    client *cl = (client *)arg;
    char id_buff[1024];
    recv(cl->fd, id_buff, 1024, 0);
    memcpy(cl->id, id_buff, 1024);

    char uid_buff[1024];
    recv(cl->fd, uid_buff, 1024, 0);
    memcpy(cl->uid, uid_buff, 1024);

    printf("client %s: has connected with uid of: %s\n", cl->id, cl->id);

#ifdef CRYPTO
    // send public key
    send(cl->fd, public_key_gen, strlen((const char *)public_key_gen), 0);

    // receive public key
    char clientPublicKey[1024];
    recv(cl->fd, cl->plainTextKey, 1024, 0);
    cl->publicKey = LoadPublicKeyFromString((const char *)cl->plainTextKey);
    // load private key for decryption

#endif
    clients.push_back(cl);
    while (cl->valid)
    {
        packet p;
        char data[sizeof(packet)] = {0};
        // int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        int bytes = recv(cl->fd, &data, sizeof(packet), 0);
        if (bytes <= 0)
            return 0;
        
#ifdef CRYPTO
        unsigned char* d = Decrypt((const u_char*)data, s_privkey);
        p.deserialize((const char*)d);
        if (!strncmp(p.type, "CLS", 3))
        {
            cl->valid = false;
            printf("%s: has disconnected\n", cl->uid);
            fsend_message("%s: has disconnected", cl->uid);
            break;
        }
        else if(!strncmp(p.type, "MSG", 3))
        {
            printf("%s: %s\n", cl->uid, p.data);
            send_message((char *)p.data, cl->uid);
        }
        else if(!strncmp(p.type, "HRT", 3))
        {
            const char* cur_time = std::to_string(time(0)).c_str();
            if (!strcmp(p.data, cur_time))
            {
                // printf("Check passed\n");
            }
        }
        
#else
        /*         printf("%s: %s\n", cl->uid, msg);*/
        if (!strncmp(p.type, "MSG", 3))
        {
            printf("%s: %s\n", cl->uid, p.data);
            send_message(p.data, cl->uid);
        }
        else if (!strncmp(p.type, "CLS", 3))
        {
            cl->valid = false;
            fsend_message("%s: has disconnected", cl->uid);
            break;
        }
#endif
    }
    vector<client *>::iterator it = std::find(clients.begin(), clients.end(), cl);
    if (it != clients.end())
    {
        clients.erase(it);
    }
    delete cl;
    return 0;
}

void segfault_handler(int signo)
{
    // Print a message indicating the segmentation fault
    send_message((char*)"Server crashed!");
    cls(-1);
    // Continue with the default signal handler for SIGSEGV
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}
