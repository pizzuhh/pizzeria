/*
server.cpp 

This file contains the code for the server side
written by: pizzuhh
*/

#include "helper.hpp"
#include <getopt.h>
#include <limits.h>
// https://files.pizzuhh.dev/pizLogger.hpp
#include "pizLogger.hpp"
#define WRITELOG(type, msg) \
do { \
    if (logging) { \
        logger->writelog<type, 0, 0>(msg); \
    } \
} while(0)

#define LOGERROR() \
if (logging) { \
    logger->logError(); \
}
#define CLOSELOGGER() \
do { \
    if (logging) { \
        logger->CloseLogger(); \
    } \
} while(0)

#define DELETELOG() \
do { \
    if (logging) { \
        logger->DeleteLog(); \
    } \
} while(0)


bool defaultPort = false, logging = false;
char *logFile;

using std::vector;
// sleep for miliseconds
#define msleep(ms) usleep(ms * 1000);
struct client
{
    int fd;
    // int id;
    char id[1024];
    char username[MAX_INPUT];
    sockaddr addr;
    bool valid = true;
#ifdef CRYPTO
    char plainTextKey[1024];
    RSA *publicKey;
#endif
};

vector<client *> clients;
Logger *logger = nullptr;


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
    WRITELOG(WARNING, "Broken pipe has been detected! (this shouldn't happen?) Could be that client has disconnected");
    fprintf(stderr, "Broken pipe has been detected! (this shouldn't happen?) Could be that client has disconnected\n");
}

// handle segfault
void segfault_handler(int signo);

// handle server closing
void cls(int c)
{
    send_message("Server has stopped");
    send_message("Do not send messages to this server");
    for (client* cl: clients)
    {
        delete cl;
    }
    WRITELOG(ERROR, formatString("Server exited: %d", c));
    printf("exited...\nyou can now press enter");
    exit(0);
}

// print help
void help(void)
{
    printf("pizzeria-server\n--log={log file} (or just --log) will log almost every action\n\
    --default-port will use the default port 5524 (used for the docker container)");
}

// main function
int main(int argc, char **argv)
{
    struct option opt[] = {
        {"log", optional_argument, 0, 'l'},
        {"default-port", no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };
    int c = -1;
    while ((c = getopt_long(argc, argv, "dl:", opt, 0)) != -1)
    {   
        switch (c)
        {
        case 'd':
            defaultPort = true;
            break;
        case 'l':
            logging = true;
            if (optarg)
            {
                logFile = optarg;
            }
            else
            {
                time_t raw;
                struct tm *timeinfo;
                char time_str[1024];

                time(&raw);
                timeinfo = localtime(&raw);
                strftime(time_str, sizeof(time_str), "pizzeria-server-%Y-%m-%d--%H:%M:%S.log", timeinfo);
                logFile = time_str;
            }
            printf("%s\n", logFile);
        default:
            break;
        }
    }
    if (logging)
    {
        logger = new Logger(logFile);
    }
    // warn if the server is not running with encryption
    #ifndef CRYPTO
    fprintf(stderr, "SERVER IS RUNNING WITHOUT ENCRYPTION!\nTO USE ENCRYPTION REBUILD THE SERVER AND THE CLIENT!\n");
    #endif
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    WRITELOG(INFO, "SIGPIPE -> broken_pipe()");
    signal(SIGINT, (sighandler_t)cls);
    WRITELOG(INFO, "SIGINT -> cls()");
    int port = 0;
    if (argc >= 2)
    {
        if (defaultPort)
        {
            port = 5524;
            WRITELOG(INFO, "Default port used: 5524");

        }
        else 
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
    }
    else
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
    /*
    following code creates a socket, binds to it and listens for connections
    */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        LOGERROR();
        exit(-1);
    }
    WRITELOG(INFO, "socket()");
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (int *)1, sizeof(int));
    WRITELOG(INFO, "setsockopt()");
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    WRITELOG(INFO, "initialized sockaddr_in addr");
    if (bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == -1)
    {
        perror("bind");
        LOGERROR();
        exit(-1);
    }
    printf("Server listens on 127.0.0.1:%d\n", port);
    if (listen(fd, 5) == -1)
    {
        perror("listen");
        LOGERROR();
        exit(-1);
    }
    WRITELOG(INFO, "Bound successfully. Listening for connections");
    int last_id = 0;
    sockaddr cl_addr;
    int socklen = sizeof(cl_addr);

#ifdef CRYPTO
    // generate private-public key pair
    GenerateKeyPair(&private_key_gen, &public_key_gen);
    s_pubkey = LoadPublicKeyFromString((const char*)public_key_gen);
    s_privkey = LoadPrivateKeyFromString((const char*)private_key_gen);
    WRITELOG(INFO, "[CRYPTO]: Generated key pairs");
#endif
    pthread_t adminClient;
    pthread_create(&adminClient, 0, server_client, 0);
    WRITELOG(INFO, "Created server client thread");
    while (true)
    {
        pthread_t p;
        int cl_fd = accept(fd, (sockaddr *)&cl_addr, (socklen_t *)&socklen);
        if (cl_fd > 0)
        {
            WRITELOG(INFO, "Accepted connection");
            last_id++;
            client *cl = new client;
            cl->fd = cl_fd;
            cl->addr = cl_addr;
            // clients.push_back(cl);
            pthread_create(&p, 0, handle_client, (void *)cl);
            WRITELOG(INFO, "Created client thread");
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
        if (std::cin.eof())
            cls(0);
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
        if (strcmp(client->username, sender))
        {
#ifdef CRYPTO
            unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
            send(client->fd, encrypted, MAX_LEN, 0);
            WRITELOG(INFO, "Message sent");

#else
            send(client->fd, s, strlen(out), 0);
            WRITELOG(INFO, "Message sent");
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
        WRITELOG(INFO, "Message sent");
#else
        send(client->fd, s, strlen(out), 0);
        WRITELOG(INFO, "Message sent");

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
        WRITELOG(INFO, "Message sent");

#else
        send(client->fd, s, strlen(s), 0);
        WRITELOG(INFO, "Message sent");

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
    WRITELOG(INFO, "Received client's ID"); // logger goes out of scope. Why?

    memcpy(cl->id, id_buff, 1024);

    char username_buffer[MAX_INPUT];
    recv(cl->fd, username_buffer, MAX_INPUT, 0);
    WRITELOG(INFO, "Received client ID");
    memcpy(cl->username, username_buffer, MAX_INPUT);

    printf("client %s: has connected with username of: %s\n", cl->id, cl->username);
    WRITELOG(INFO, formatString("client %s: has connected with username of: %s", cl->id, cl->username));

#ifdef CRYPTO
    // send public key
    send(cl->fd, public_key_gen, strlen((const char *)public_key_gen), 0);
    WRITELOG(INFO, "Sent server's public key");
    // receive public key
    char clientPublicKey[1024];
    recv(cl->fd, cl->plainTextKey, 1024, 0);
    WRITELOG(INFO, "Received client public key");
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
            printf("%s: has disconnected\n", cl->username);
            fsend_message("%s: has disconnected", cl->username);
            WRITELOG(INFO, formatString("%s: has disconnected", cl->username));
            break;
        }
        else if(!strncmp(p.type, "MSG", 3))
        {
            printf("%s: %s\n", cl->username, p.data);
            send_message((char *)p.data, cl->username);
            WRITELOG(INFO, formatString("%s: %s", cl->username));
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
        /*         printf("%s: %s\n", cl->username, msg);*/
        if (!strncmp(p.type, "MSG", 3))
        {
            printf("%s: %s\n", cl->username, p.data);
            send_message(p.data, cl->username);
            WRITELOG(INFO, formatString("%s: %s", cl->username));

        }
        else if (!strncmp(p.type, "CLS", 3))
        {
            cl->valid = false;
            fsend_message("%s: has disconnected", cl->username);
            WRITELOG(INFO, formatString("%s: has disconnected", cl->username));
            break;
        }
#endif
    }
    vector<client *>::iterator it = std::find(clients.begin(), clients.end(), cl);
    if (it != clients.end())
    {
        clients.erase(it);
        WRITELOG(INFO, "Erased client");

    }
    delete cl;
    return 0;
}

void segfault_handler(int signo)
{
    // Print a message indicating the segmentation fault
    send_message((char*)"Server crashed!");
    WRITELOG(ERROR, "Server received segmentation fault!");
    cls(-1);
    // Continue with the default signal handler for SIGSEGV
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}
