#pragma once
#include <openssl/sha.h>
/*
This has the implementations of most functions used server.cpp
from the client code to keep it clean

Also will be used for the GUI app
*/

#include "utils.hpp"
#include <getopt.h>
#include <limits.h>
#include <regex>
#include <map>

std::fstream cfg;
json _json;
std::map<std::string, std::string> banned;
std::vector<std::string> filterKeywords;
std::string words;
bool filter_on;
uint8_t filter_mode;
char *cfg_path;

enum filter_mode_enum {
    DO_NOT_SEND_MESSAGE = 0,
    KICK_USER = 1,
    BAN_USER = 2
};


int load_config();
void *handle_client(void *arg);
void *server_client(void *arg);
void send_message(char *msg, char *sender);
void send_message(const char *msg);
void fsend_message(char *fmt, ...);

// https://files.pizzuhh.dev/pizLogger.hpp
#include "pizLogger.hpp"
#define WRITELOG(type, msg) logging == true ? logger->writelog<type, 0, 0>(msg) : (void)0


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
    char id[1024];
    char username[MAX_INPUT];
    sockaddr_in addr;
    bool valid = true;
    char hashedIp[32];
    char clientSettings; // 8 bit value for 8 settings. (Idk how many of them will be used but 1 surely will so we go with minimum size)
    char plainTextKey[1024];
    EVP_PKEY *publicKey;
};

vector<client *> clients;
Logger *logger = nullptr;
void ban (client &cl);

int load_config() {
    cfg.open(cfg_path, std::ios::app | std::ios::in | std::ios::out);
    if (!cfg.is_open()) return 0;
    cfg.seekg(0, std::ios::beg);
    std::string cfg_data((std::istreambuf_iterator<char>(cfg)), std::istreambuf_iterator<char>());
    cfg.close();
    _json = json::parse(cfg_data);
    filter_on       = _json["filter"]["enabled"];
    filter_mode     = _json["filter"]["mode"];
    words.clear();
    if (_json["filter"]["filter"].is_array()) {
        for (const auto &item : _json["filter"]["filter"]) {
            words.append(item.get<std::string>() + "|");
        }
        if (!words.empty()) words.pop_back();
    }
    banned.clear();
    if (_json["banned-clients"].is_array()) {
        banned.clear();
        for (const auto &item : _json["banned-clients"]) {
            if (item.is_object() && !item.is_null()) {
                for (const auto &i : item.items()) {
                    banned[i.key()] = i.value().get<std::string>();
                }
            }
        }
    }
    WRITELOG(INFO, "Loaded/Reloaded config!");
    return 1;
}


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
    //u_char *data = Encrypt((const u_char*)buff, cl.publicKey);
    int size;
    unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
    //unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
    send(cl.fd, encrypted, size, 0);
    delete[] s;
}


void *parse_command(const std::string command) {
    std::vector args = split(command);
    if      (args[0] == "help") {
        printf("Help command...\n"\
        "- kick <user> <reason> -> kicks user with reason\n"\
        "- lsmem -> lists information about all connected members\n"\
        "- ban <member> -> bans a member from the server\n"\
        "- cfgrld -> reloads the config\n"\
        "- unbab <member> -> unbans a member from the server\n"\
        "[DEBUG ONLY] - CRASH -> crashes the server via segfault. (do not use)\n");
    }
    else if (args[0] == "kick") {
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
    else if (args[0] == "lsmem") {
        for (client *cl : clients) { 
            printf("Name: %s\nUUID:%s\nHashed-Ip: %s\nFD:%d\n\n", 
            cl->username, cl->id, cl->hashedIp, cl->fd);
        }
    }
    else if (args[0] == "ban") {
        if (args[1].empty()) {
            printf("Ban requires user name!\n"); return nullptr;
        }
        for (client *c : clients) {
            if (!strcmp(c->username, args[1].c_str())) {
                packet2 p("Banned from the server", "", "", packet_type::SERVER_CLIENT_KICK);
                WRITELOG(INFO, formatString("Kicked %s, reason: %s", c->username, p.data));
                send_p(p, *c);
                ban(*c);
            }
        }
    }
    else if (args[0] == "cfgrld") {
        load_config();
    }
    else if (args[0] == "unban") {
        if (args[1].empty()) fprintf(stderr, "#! ban <member>. Member argument not provided!\n");
        auto it = banned.find(args[1]);
        if (it == banned.end()) fprintf(stderr, "Couldn't not find member\n");
        banned.erase(it);
        _json["banned-clients"].clear();
        if (!banned.empty()) {
            for (const auto &mem : banned) {
                json m;
                m[mem.first] = mem.second;
                _json["banned-clients"].push_back(m);
            }
        }
        cfg.open(cfg_path, std::ios::out | std::ios::trunc);
        cfg.write(_json.dump(4).c_str(), _json.dump(4).size());
        cfg.flush();
        cfg.close();
    }
    else if (args[0] == "CRASH") {
        #ifdef DEBUG
        WRITELOG(WARNING, "Controlled crash executed.");
        char *p;
        *p=1;
        #else
        printf("This command is only for debug mode\n");
        #endif
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
            int size;
            unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
            send(client->fd, encrypted, size, 0);
            WRITELOG(INFO, "Message sent");
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
     int size;
    unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
    for (const auto &client : clients) {   
        send(client->fd, encrypted, size, 0);
        WRITELOG(INFO, "Message sent");
    }
    delete[] s;
    delete[] out;
}
void fsend_message(const char *format, ...) {
    char *out = new char[1024*2];
    char *tmp = new char[MAX_LEN];

    va_list args;
    va_start(args, format);

    vsnprintf(tmp, MAX_LEN, format, args);

    va_end(args);
    sprintf(out, "[SERVER]: %s", tmp);
    packet2 p(out, "the higher-ups", "", packet_type::MESSAGE);
    char *s = p.serialize();
    for (const auto &client : clients) {
        int size;
        unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
        send(client->fd, encrypted, size, 0);
        WRITELOG(INFO, "Message sent");
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
    //unsigned char *encrypted = Encrypt((const unsigned char *)s, target->publicKey);
    int size;
    unsigned char *encrypted = aes_encrypt((u_char*)s, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
    //unsigned char *encrypted = Encrypt((const unsigned char *)s, client->publicKey);
    send(target->fd, encrypted, size, 0);
    delete[] s;
    delete[] out;
}
void send_message(char* msg, char* sender, char* receiver) {
    for (auto &it : clients) {
        if (!strcmp(receiver, it->username)) {
            char *out = new char[PACKET_SIZE];
            packet2 p(msg, receiver, sender, packet_type::PRIVATE_MESSAGE);
            char *data = p.serialize();
            int size;
            unsigned char *encrypted = aes_encrypt((u_char*)data, PACKET_SIZE, server_aes_key, server_aes_iv, &size);
            send(it->fd, encrypted, size, 0);
            delete[] out;
            delete[] data;
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
    json obj;
    obj[cl.username] = cl.hashedIp;
    _json["banned-clients"].push_back(obj);
    banned.insert({cl.username, cl.hashedIp});
    cfg.open(cfg_path, std::ios::out | std::ios::trunc);
    cfg.write(_json.dump(4).c_str(), _json.dump(4).size());
    cfg.flush();
    cfg.close();
}

void *handle_client(void *arg) {
    client *cl = (client *)arg;
    
    socklen_t cl_addr_len = sizeof(cl->addr);
    getpeername(cl->fd, (sockaddr*)&cl->addr, &cl_addr_len);
    
    // variables
    u_char *hashed_ip = new u_char[32];
    char *hashed_ip_hex = new char[65];
    char buffer[PACKET_SIZE];
    packet2 p;
    char *m = nullptr;
    char id_buff[1024];
    char username_buffer[MAX_INPUT];
    char clientPublicKey[1024];
    unsigned char* encrypted_aes_key; 
    size_t len;
    EVP_PKEY *key = nullptr;

    recv(cl->fd, buffer, PACKET_SIZE, 0);
    packet2 tmp = packet2::deserialize(buffer);
    switch (tmp.type)
    {
    case packet_type::PING:
        send(cl->fd, "PONG", 5, 0);
        goto cleanup;
        break;
    default:
        break;
    }
    
    SHA256((u_char*)inet_ntoa(cl->addr.sin_addr), strlen(inet_ntoa(cl->addr.sin_addr)+1), hashed_ip);
    for (size_t i = 0; i < 32; i++)
    {
        snprintf(&hashed_ip_hex[i*2], 3, "%02X", hashed_ip[i]);
    }
    delete[] hashed_ip;
    strncpy(cl->hashedIp, (char*)hashed_ip_hex, 32);
    
    for (auto &hash : banned) {
        if (hash.second == cl->hashedIp) {
            p = packet2(packet_type::SERVER_CLIENT_KICK);
            cl->valid = false;
            char *m = p.serialize();
            send(cl->fd, m, PACKET_SIZE, 0);
            return nullptr;
        }
    }
    p = packet2(packet_type::GENERIC);
    m = p.serialize();
    send(cl->fd, m, PACKET_SIZE, 0);

    WRITELOG(INFO, format_string("Client's hashed ip: %s", hashed_ip_hex));
    
    recv(cl->fd, id_buff, 1024, 0);
    WRITELOG(INFO, "Received client's ID");
    memcpy(cl->id, id_buff, 1024);

    
    recv(cl->fd, username_buffer, MAX_INPUT, 0);
    WRITELOG(INFO, "Received client ID");
    memcpy(cl->username, username_buffer, MAX_INPUT);

    printf("client %s: has connected with username of: %s\n", cl->id, cl->username);
    WRITELOG(INFO, formatString("client %s: has connected with username: %s", cl->id, cl->username));

    // receive public key
    
    recv(cl->fd, clientPublicKey, 1024, 0);
    WRITELOG(INFO, "Received client public key");
    key = deserializeEVP_PKEY(clientPublicKey);
    
    
    
    rsa_encrypt(server_aes_key, sizeof(server_aes_key), key, &encrypted_aes_key, &len);
    send(cl->fd, encrypted_aes_key, 256, 0);
    send(cl->fd, server_aes_iv, sizeof(server_aes_iv), 0);
    WRITELOG(INFO, "Sending aes key and iv");
    clients.push_back(cl);
    // send_message("test", cl->username, cl->username);
    
    while (cl->valid) {
        packet2 p;
        u_char *data = new u_char[1552];
        // int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        int bytes = recv(cl->fd, data, 1552, 0);
        if (bytes <= 0)
            return 0;
        
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
                            p_mod = packet2("Kicked by filter.", "", "", packet_type::SERVER_CLIENT_KICK);
                            send_p(p_mod, *cl);
                            break;
                        // TODO(5): Implement the ban logic. For now kick the user
                        case BAN_USER: 
                            printf("!FILTERED <%s>: %s\n", cl->username, p.data);
                            WRITELOG(INFO, formatString("(%s: %s) Has been flagged (and banned) by the filter!", cl->username, p.data));
                            send_message("Your message has been flagged by the filter!", cl);
                            p_mod = packet2("Kicked by filter.", "", "", packet_type::SERVER_CLIENT_KICK);
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
                WRITELOG(INFO, formatString("%s: %s", cl->username, p.data));
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
            strncpy(target, pm.substr(0, pos).c_str(), sizeof(p.receiver)-1);
            target[sizeof(target) - 1] = '\0'; 
            strncpy(msg, pm.substr(pos + 1).c_str(), sizeof(p.data)-1);
            msg[sizeof(msg) - 1] = '\0'; 
            send_message(msg, cl->username, target);
        }
        else if (p.type == packet_type::CLIENT_CLOSE) {
            printf("%s has disconnected\n", cl->username);
            send_message(format_string("%s: has disconnected", cl->username));
            break;
        }
    }
    cleanup:
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
    WRITELOG(ERROR, "Server has crashed. Building it in debug mode and replacing the crash will help solving it.");
    WRITELOG(ERROR, "Make an issue here: https://github.com/pizzuhh/pizzeria/issues/new");
    send_message("SERVER HAS CRASHED! PLEASE DISCONNECT!");
    // Continue with the default signal handler for SIGSEGV
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}
