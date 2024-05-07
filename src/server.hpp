#pragma once
/*
This has the implementations of most functions used server.cpp
from the client code to keep it clean

Also will be used for the GUI app
*/

#include "helper.hpp"
#include <getopt.h>
#include <limits.h>
#include <regex>

std::vector<std::string> filterKeywords;
std::string words;
bool filter_on;
uint8_t filter_mode;
enum filter_mode_enum {
    DO_NOT_SEND_MESSAGE = 0,
    KICK_USER = 1,
    BAN_USER = 2
};

void *handle_client(void *arg);
void *server_client(void *arg);
void send_message(char *msg, char *sender);
void send_message(const char *msg);
void fsend_message(char *fmt, ...);

// https://files.pizzuhh.dev/pizLogger.hpp
#include "pizLogger.hpp"
/* #define WRITELOG(type, msg) \
do { \
    if (logging) { \
        logger->writelog<type, 0, 0>(msg); \
    } \
} while(0) */

#define WRITELOG(type, msg) logging == true ? logger->writelog<type, 0, 0>(msg) : (void)0

/* #define LOGERROR() \
if (logging) { \
    logger->logError(); \
} */

#define LOGERROR() logging == true ? logger->logError() : (void)0

#define CLOSELOGGER() logging == true ? logger->CloseLogger() : (void)0

#define DELETELOG() logging == true ? logger->DelteLog() : (void)0


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

void cls(int c)
{
    send_message("Server has stopped");
    send_message("Do not send messages to this server");
    for (client* cl: clients)
    {
        delete cl;
    }
    WRITELOG(WARNING, "Server exited");
    delete logger;
    printf("exited...\nyou can now press enter");
    exit(0);
}

void help(void)
{
    printf("pizzeria-server\n\
    --log={log file} (or just --log) will log almost every action\n\
    --default-port will use the default port 5524 (used for the docker container)");
}


void send_p(packet p, client cl)
{
    char* buff = p.serialize();
    #ifdef CRYPTO
    u_char *data = Encrypt((const u_char*)buff, cl.publicKey);
    send(cl.fd, data, sizeof(packet), 0);
    #else
    send(cl.fd, buff, sizeof(packet), 0);
    #endif
}


void *parse_command(const std::string command) {
    std::vector args = split(command);
    if (args[0] == "kick") {
        packet p("KIC", "UNKOWN");
        if (args.size() < 2) {
            fprintf(stderr, "args[1]: empty\n");
        }
        if (args.size() >= 3) {
            std::string d;
            for (size_t i = 2; i < args.size(); i++)
            {
                
                d.append(args[i] + ' ');
                
            }
            strncpy(p.data, d.c_str(), 1024);
        }
        const char *target = args[1].c_str();
        for (client *c : clients) {
            if (!strcmp(c->username, target)) {
                WRITELOG(INFO, formatString("Kicked %s, reason: %s", target, p.data));
                send_p(p, *c);
            }
        }
    }
    return 0;
}

void *server_client(void *arg)
{
    std::string buff;
    while (1) {

        printf("\nMessage: ");
        
        std::getline(std::cin, buff);
        if (std::cin.eof())
            cls(0);
        if (buff.substr(0, 2) == "#!") {
            parse_command(buff.substr(2));
        } else {
            send_message(const_cast<char *>(buff.c_str()));
        }
        
    }

    return nullptr;
}

void send_message(char *msg, char *sender)
{
    char *out = new char[KiB(4)];
    sprintf(out, "<%s>: %s", sender, msg);
    packet p;
    strncpy(p.type, "MSG", 4);
    strncpy(p.data, out, MAX_LEN);
    char* s = p.serialize();
    for (const auto &client : clients) {
        if (strcmp(client->username, sender)) {
#ifdef CRYPTO
            unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
            send(client->fd, encrypted, sizeof(packet), 0);
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
void send_message(const char *msg) {
    char *out = new char[KiB(4)];
    sprintf(out, "%s: %s", "[SERVER]", msg);
    packet p;
    strncpy(p.type, "MSG", 4);
    strncpy(p.data, out, MAX_LEN);
    char* s = p.serialize();
    for (const auto &client : clients) {   
#ifdef CRYPTO
        unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
        send(client->fd, encrypted, sizeof(packet), 0);
        WRITELOG(INFO, "Message sent");
#else
        send(client->fd, s, sizeof(packet), 0);
        WRITELOG(INFO, "Message sent");

#endif
    }
    free(s);
    delete[] out;
}
void fsend_message(const char *format, ...) {
    char *out = new char[sizeof(packet)];
    char *tmp = new char[MAX_LEN];

    va_list args;  // Define a variable argument list
    va_start(args, format);  // Initialize the argument list

    // Use vsnprintf to format the string with variable arguments
    vsnprintf(tmp, MAX_LEN, format, args);

    va_end(args);  // Clean up the argument list
    sprintf(out, "[SERVER]: %s", tmp);
    packet p("MSG", out);
    char *s = p.serialize();
    for (const auto &client : clients) {
#ifdef CRYPTO
        unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
        send(client->fd, encrypted, sizeof(packet), 0);
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
void send_message(const char *msg, const client *target) {
    char *out = new char[KiB(4)];
    sprintf(out, "%s: %s", "[SERVER]", msg);
    packet p;
    strncpy(p.type, "MSG", 4);
    strncpy(p.data, out, MAX_LEN);
    char* s = p.serialize();  
    #ifdef CRYPTO
        unsigned char *encrypted = Encrypt((const unsigned char *)s, target->publicKey);
        send(target->fd, encrypted, sizeof(packet), 0);
    #else
        send(target->fd, s, sizeof(packet), 0);
    #endif
    delete[] s;
    delete[] out;
}
void send_message(char* msg, char* sender, char* receiver) {
    for (auto &it : clients) {
        if (!strcmp(receiver, it->username)) {
            char *out = new char[KiB(5)];
            sprintf(out, "[<%s> -> <%s>]: %s", sender, receiver, msg);
            packet *p = nullptr;
            #ifdef CRYPTO
            p = new packet("PVM", out);
            char *data = p->serialize();
            unsigned char *enc = Encrypt((const u_char*)data, it->publicKey);
            send(it->fd, enc, sizeof(packet), 0);
            #endif
            delete[] out;
            delete p;
            return;
        }
    }
    auto it = std::find_if(clients.begin(), clients.end(), [&](client *c) {
        return strcmp(c->username, sender) == 0;
    });
    client *cl = *it;
    if (it != clients.end())
        send_message("User does not exist!", cl);
}

bool filterMessage(const std::string &message) {
    std::string pattern = "(" + words + ")";
    std::regex reg(pattern);
    std::smatch matches;
    if (std::regex_search(message, matches, reg)) {
        return true;
    }
    return false;
}

void ban (client &cl) {
    //TODO(5): Implement it lol
}

void *handle_client(void *arg) {
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
    //char clientPublicKey[1024];
    recv(cl->fd, cl->plainTextKey, 1024, 0);
    WRITELOG(INFO, "Received client public key");
    cl->publicKey = LoadPublicKeyFromString((const char *)cl->plainTextKey);
    // load private key for decryption

#endif
    clients.push_back(cl);
    // send_message("test", cl->username, cl->username);
    while (cl->valid) {
        packet p;
        char data[sizeof(packet)] = {0};
        // int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        int bytes = recv(cl->fd, &data, sizeof(packet), 0);
        if (bytes <= 0)
            return 0;
        
#ifdef CRYPTO
        unsigned char* d = Decrypt((const u_char*)data, s_privkey);
        p.deserialize((const char*)d);
        if (!strncmp(p.type, "CLS", 3)) {
            cl->valid = false;
            printf("%s: has disconnected\n", cl->username);
            fsend_message("%s: has disconnected", cl->username);
            WRITELOG(INFO, formatString("%s: has disconnected", cl->username));
            break;
        } else if(!strncmp(p.type, "MSG", 3)) {
            
            if (filter_on) {
                if (!filterMessage(p.data)) {
                    printf("<%s>: %s\n", cl->username, p.data);
                    send_message((char *)p.data, cl->username);
                    WRITELOG(INFO, formatString("%s: %s", cl->username, p.data));
                } else {
                    packet p_mod;
                    switch (filter_mode) {
                        case DO_NOT_SEND_MESSAGE:
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            break;
                        case KICK_USER:
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged (and kicked) by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            p_mod = packet("KIC", "Kicked by filter");
                            send_p(p_mod, *cl);
                            break;
                        // TODO(5): Implement the ban logic. For now kick the user
                        case BAN_USER: 
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged (and banned) by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            p_mod = packet("KIC", "Banned (kicked) by filter");
                            send_p(p_mod, *cl);
                            break;
                        default:
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            break;
                    }
                }
            } else {
                send_message((char *)p.data, cl->username);
                WRITELOG(INFO, formatString("%s: %s", cl->username, p.data));
            }
        } else if (!strncmp(p.type, "PVM", 3)) {
            std::string pm(p.data);
            char target[256]; // Adjust the size as needed
            char msg[256]; // Adjust the size as needed
            size_t pos = pm.find(' ');
            if (pos == std::string::npos) {
                send_message("Error while sending message!", cl); 
                continue;
            }
            strncpy(target, pm.substr(0, pos).c_str(), sizeof(target));
            target[sizeof(target) - 1] = '\0'; // Ensure null-termination
            strncpy(msg, pm.substr(pos + 1).c_str(), sizeof(msg));
            msg[sizeof(msg) - 1] = '\0'; // Ensure null-termination
            send_message(msg, cl->username, target); // Make sure send_message is properly implemented
        }
#else
        p.deserialize((const char*)data);
        /*         printf("%s: %s\n", cl->username, msg);*/
        if (!strncmp(p.type, "MSG", 3)) {
            printf("<%s>: %s\n", cl->username, p.data);
            send_message(p.data, cl->username);
            WRITELOG(INFO, formatString("%s: %s", cl->username, p.data));
        }
        else if (!strncmp(p.type, "CLS", 3)) {
            cl->valid = false;
            fsend_message("%s: has disconnected", cl->username);
            WRITELOG(INFO, formatString("%s: has disconnected", cl->username));
            break;
        }
#endif
    }
    vector<client *>::iterator it = std::find(clients.begin(), clients.end(), cl);
    if (it != clients.end()) {
        clients.erase(it);
        WRITELOG(INFO, "Erased client");

    }
    delete cl;
    return 0;
}

void segfault_handler(int signo) {
    // Print a message indicating the segmentation fault
    send_message((char*)"Server crashed!");
    WRITELOG(ERROR, "Server received segmentation fault!");
    send_message("SERVER HAS CRASHED! PLEASE DISCONNECT!");
    // Continue with the default signal handler for SIGSEGV
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}
