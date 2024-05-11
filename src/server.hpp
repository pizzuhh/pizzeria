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
    EVP_PKEY *publicKey;
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


void send_p(packet2 p, client cl)
{
    char* s = p.serialize();
    #ifdef CRYPTO
    //u_char *data = Encrypt((const u_char*)buff, cl.publicKey);
    int size;
    unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
    //unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
    send(cl.fd, encrypted, size, 0);
    #else
    send(cl.fd, s, sizeof(packet), 0);
    #endif
    delete[] s;
}


void *parse_command(const std::string command) {
    std::vector args = split(command);
    if (args[0] == "kick") {
        packet2 p(packet_type::SERVER_CLIENT_KICK);
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
    char *out = new char[PACKET_SIZE];
    sprintf(out, "<%s>: %s", sender, msg);
    packet2 p(out, sender, "", packet_type::MESSAGE);
    char* s = p.serialize();
    for (const auto &client : clients) {
        if (strcmp(client->username, sender)) {
            #ifdef CRYPTO
            int size;
            unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
            send(client->fd, encrypted, size, 0);
            WRITELOG(INFO, "Message sent");
            #else
            send(client->fd, s, PACKET_SIZE, 0);
            WRITELOG(INFO, "Message sent");
            #endif
        }
    }
    delete[] s;
    delete[] out;
}
void send_message(const char *msg) {
    char *out = new char[snprintf(nullptr, 0, "%s: %s", "[SERVER]", msg)+1];
    sprintf(out, "%s: %s", "[SERVER]", msg);
    packet2 p(out, "the higher-ups", "", packet_type::MESSAGE);
    char* s = p.serialize();
    #ifdef CRYPTO
     int size;
    unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
    #endif
    for (const auto &client : clients) {   
        #ifdef CRYPTO
        send(client->fd, encrypted, size, 0);
        WRITELOG(INFO, "Message sent");
        #else
        send(client->fd, s, sizeof(packet), 0);
        WRITELOG(INFO, "Message sent");
        #endif
    }
    delete[] s;
    delete[] out;
}
void fsend_message(const char *format, ...) {
    char *out = new char[sizeof(packet)];
    char *tmp = new char[MAX_LEN];

    va_list args;
    va_start(args, format);

    vsnprintf(tmp, MAX_LEN, format, args);

    va_end(args);
    sprintf(out, "[SERVER]: %s", tmp);
    packet2 p(out, "the higher-ups", "", packet_type::MESSAGE);
    char *s = p.serialize();
    for (const auto &client : clients) {
    #ifdef CRYPTO
        int size;
        unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
        send(client->fd, encrypted, size, 0);
        WRITELOG(INFO, "Message sent");

    #else
        send(client->fd, s, strlen(s), 0);
        WRITELOG(INFO, "Message sent");

    #endif
    }
    delete[] s;
    delete[] out;  
    delete[] tmp;
}
void send_message(const char *msg, const client *target) {
    char *out = new char[KiB(4)];
    sprintf(out, "%s: %s", "[SERVER]", msg);
    packet2 p(out, "the higher-ups", "", packet_type::MESSAGE);
    char* s = p.serialize();  
    #ifdef CRYPTO
        //unsigned char *encrypted = Encrypt((const unsigned char *)s, target->publicKey);
        int size;
        unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
        //unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
        send(target->fd, encrypted, size, 0);
    #else
        send(target->fd, s, sizeof(packet), 0);
    #endif
    delete[] s;
    delete[] out;
}
void send_message(char* msg, char* sender, char* receiver) {
    for (auto &it : clients) {
        if (!strcmp(receiver, it->username)) {
            char *out = new char[PACKET_SIZE];
            packet2 p(msg, receiver, sender, packet_type::PRIVATE_MESSAGE);
            #ifdef CRYPTO
            char *data = p.serialize();
            int size;
            unsigned char *encrypted = aes_encrypt((u_char*)data, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
            send(it->fd, encrypted, size, 0);
            #endif
            delete[] out;
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
    // receive public key
    char clientPublicKey[1024];
    recv(cl->fd, clientPublicKey, 1024, 0);
    WRITELOG(INFO, "Received client public key");
    EVP_PKEY *key = deserializeEVP_PKEY(clientPublicKey);
    
    unsigned char* encrypted_aes_key; 
    size_t len;
    
    rsa_encrypt(server_aes_key, sizeof(server_aes_key), key, &encrypted_aes_key, &len);
    send(cl->fd, encrypted_aes_key, 256, 0);
    send(cl->fd, server_aes_iv, sizeof(server_aes_iv), 0);
    #endif
    clients.push_back(cl);
    // send_message("test", cl->username, cl->username);
    
    while (cl->valid) {
        packet2 p;
        u_char *data = new u_char[1552];
        // int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        int bytes = recv(cl->fd, data, 1552, 0);
        if (bytes <= 0)
            return 0;
        
        #ifdef CRYPTO
        int size;
        unsigned char* d = aes_decrypt(data, 1552, server_aes_key, server_aes_iv, &size);
        p = packet2::deserialize((char*)d);
        if (p.type == packet_type::MESSAGE) {
            if (filter_on) {
                if (!filterMessage(p.data)) {
                    printf("<%s>: %s\n", cl->username, p.data);
                    send_message((char *)p.data, cl->username);
                    WRITELOG(INFO, formatString("%s: %s", cl->username, p.data));
                } else {
                    packet2 p_mod;
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
                            p_mod = packet2(packet_type::SERVER_CLIENT_KICK);
                            send_p(p_mod, *cl);
                            break;
                        // TODO(5): Implement the ban logic. For now kick the user
                        case BAN_USER: 
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged (and banned) by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            p_mod = packet2(packet_type::SERVER_CLIENT_KICK);
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
                printf("<%s>: %s\n", cl->username, p.data);
                send_message(p.data, cl->username);
            }
        }
        else if (p.type == packet_type::PRIVATE_MESSAGE) {
            std::string pm(p.data);
            char target[sizeof(p.receiver)]; // Adjust the size as needed
            char msg[sizeof(p.data)]; // Adjust the size as needed
            size_t pos = pm.find(' ');
            if (pos == std::string::npos) {
                send_message("Error while sending message!", cl); 
                continue;
            }
            strncpy(target, pm.substr(0, pos).c_str(), sizeof(p.receiver));
            target[sizeof(target) - 1] = '\0'; // Ensure null-termination
            strncpy(msg, pm.substr(pos + 1).c_str(), sizeof(p.data));
            msg[sizeof(msg) - 1] = '\0'; // Ensure null-termination
            send_message(msg, cl->username, target); // Make sure send_message is properly implemented
        }
        else if (p.type == packet_type::CLIENT_CLOSE) {
            printf("%s has disconnected\n", cl->username);
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
