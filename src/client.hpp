#pragma once
/*
This has the implementations of: term, rcv, snd and the other functions
from the client code to keep it clean

Also will be used for the GUI app
*/

#include  "utils.hpp"
//#include <libnotify/notify.h>


bool running = true, connected = false;
int client_socket = 0;
pthread_t t_send, t_recv;

char pubkey[1024];
u_char *publicKey, *privateKey;
RSA* c2s_pubkey;


void term(bool ab = false, const char* message = "")
{
    /* running = false;
    send(client_socket, "#!CLOSE", 7, 0);
    close(client_socket);
    pthread_detach(t_recv); pthread_detach(t_send);
    exit(0); */
    if (connected) {
        running = false;
        packet2 p(packet_type::CLIENT_CLOSE);
        char* s = p.serialize();
        int size;
        u_char* enc = aes_encrypt((u_char*)s, PACKET_SIZE, client_aes_key, client_aes_iv, &size);
        send(client_socket, enc, size, 0);
        // detach the threads
        pthread_cancel(t_recv);pthread_join(t_recv, 0); pthread_cancel(t_send);pthread_join(t_send, 0);
    }
    //notify_uninit();
    // exit
    if (ab) abort();
    else std::exit(0);
}

void *rcv(void *arg) {
    u_char *buff = new u_char[PADDED_PACKET_SIZE];
    while (running) {
        size_t bytes = recv(client_socket, buff, PADDED_PACKET_SIZE, 0);
        if (bytes <= 0) continue;
        int len;
        u_char *dec = aes_decrypt(buff, PADDED_PACKET_SIZE, client_aes_key, client_aes_iv, &len); 
        packet2 p = packet2::deserialize((char*)dec);
        
        if (p.type == packet_type::MESSAGE) {
            printf("%s\n", p.data);
        }
        if (p.type == packet_type::PRIVATE_MESSAGE) {
            printf("[<%s> -> <%s>]: %s\n", p.sender, p.receiver, p.data);
        }
        if (p.type == packet_type::SERVER_CLIENT_KICK) {
            printf("You have been kicked by server administrator.\nReason: %s\n", (strlen(p.data) > 0) ? p.data : "UNKOWN");
            term();
        }
        memset(buff, 0, PADDED_PACKET_SIZE);
    }
    delete[] buff;
    return nullptr;
}
void send_message_private(std::string msg)
{
    packet2 p(msg.c_str(), "", "", packet_type::PRIVATE_MESSAGE);
    char* out = p.serialize();
    //u_char* buffer = Encrypt((const unsigned char*)out, c2s_pubkey);
    int size;
    u_char* buffer = aes_encrypt((u_char*)out, PACKET_SIZE, client_aes_key, client_aes_iv, &size);
    if (send(client_socket, buffer, size, 0) == -1) {
        perror("send");
        term(true);
    }
    
}
void send_message (std::string msg) {
    packet2 p (msg.c_str(), "", "", packet_type::MESSAGE);
    char *data = p.serialize();
    int len;
    u_char *encrypted = aes_encrypt ((u_char*)data, 1537, client_aes_key, client_aes_iv, &len);
    send(client_socket, encrypted, len, 0);
    delete[] data;
}
void *snd(void *arg)
{
    std::string msg;
    
    while (running) {
        if (std::cin.eof())
            term();
        std::getline(std::cin, msg);
        if (msg.empty()) {
            fprintf(stderr, "Do not send empty messages!\n");
            continue;
        }
        if (msg.substr(0, 2) != "#!") send_message(msg);
        else {
            msg.erase(0, 2);
            if (msg.substr(0, 2) == "pm") {
                msg.erase(0, 3);
                send_message_private(msg);
            }
        }
    }
    
    return nullptr;
}
