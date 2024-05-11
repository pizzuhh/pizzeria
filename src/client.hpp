#pragma once
/*
This has the implementations of: term, rcv, snd and the other functions
from the client code to keep it clean

Also will be used for the GUI app
*/

#include  "helper.hpp"
//#include <libnotify/notify.h>


bool running = true, connected = false;
int client_socket = 0;
pthread_t t_send, t_recv;

#ifdef CRYPTO
char pubkey[1024];
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
    if (connected) {
        running = false; // disable the client
        packet p; // packet
        strncpy(p.type, "CLS\0", 4); // set the packet type to "CLS" -> CLOSE
        strncpy(p.data, "DISCONNECTED", MAX_LEN); // set p.data
        char* s = p.serialize(); // turn the packet to string
        #ifdef CRYPTO // for encryption support
        // u_char* enc = Encrypt((const u_char*)s, c2s_pubkey); // encrypt the string
        int size;
        u_char* enc = aes_encrypt((u_char*)s, sizeof(packet), client_aes_key, client_aes_iv, &size);
        send(client_socket, enc, size, 0);
        #else 
        send(client_socket, s, sizeof(packet), 0);
        #endif
        // detach the threads
        pthread_cancel(t_recv);pthread_join(t_recv, 0); pthread_cancel(t_send);pthread_join(t_send, 0);
    }
    //notify_uninit();
    // exit
    if (ab) abort();
    else std::exit(0);
}

void *rcv(void *arg)
{
    #ifdef CRYPTO
    //RSA* privkey = LoadPrivateKeyFromString((const char*)privateKey);
    #endif
    u_char *buff = new u_char[1040];
    while (running) {
        int bytes = recv(client_socket, buff, 1040, 0);
        if (bytes <= 0)
            continue;
        else {
            packet *p = new packet;
            #ifdef CRYPTO
            int size;
            u_char* decrypted = aes_decrypt(buff, 1040, client_aes_key, client_aes_iv, &size);
            //u_char* decrypted = Decrypt((const u_char*)buff, privkey);
            p->deserialize((const char*)decrypted);
            if (!strncmp(p->type, "MSG", 4)) {
                printf("%s\n", p->data);
            } else if (!strncmp(p->type, "PVM", 4)) {
                
                /* A bit broken for now
                NotifyNotification *notification = notify_notification_new("Private Message", p->data, NULL);
                notify_notification_set_timeout(notification, 4000);
                notify_notification_show(notification, NULL); */
                printf("%s\n", p->data);
                //g_object_unref(G_OBJECT(notification));
            } else if (!strncmp(p->type, "KIC", 4)) {
                std::string reason;
                if (strlen(p->data) <= 0) {
                    reason = "UNKNOWN";
                } else {
                    reason = p->data;
                }
                printf("You have been kicked by the server owner! Reason: %s", reason.c_str());
                term();
            }
            #else
            p->deserialize((const char*)buff);
            if (!strncmp(p->type, "MSG", 4)) {
                printf("%s\n", p->data);
            } else if (!strncmp(p->type, "PVM", 4)) {
                
                /* A bit broken for now
                NotifyNotification *notification = notify_notification_new("Private Message", p->data, NULL);
                notify_notification_set_timeout(notification, 4000);
                notify_notification_show(notification, NULL); */
                printf("%s\n", p->data);
                //g_object_unref(G_OBJECT(notification));
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
        //u_char* buffer = Encrypt((const unsigned char*)out, c2s_pubkey, sizeof(packet));
        int size;
        u_char* buffer = aes_encrypt((u_char*)out, sizeof(packet), client_aes_key, client_aes_iv, &size);
        if (send(client_socket, buffer, size, 0) == -1) {
            perror("send");
            term(true);
        }
        #else
        strncpy(p->type, "MSG", 4);
        strncpy(p->data, (char*)msg.c_str(), sizeof(packet));
        char *buffer_noenc = p->serialize();
        //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
        if (send(client_socket, buffer_noenc, sizeof(packet), 0) == -1) {
            perror("send");
            term(true);
        }
        delete[] buffer_noenc;
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
    //u_char* buffer = Encrypt((const unsigned char*)out, c2s_pubkey);
    int size;
    u_char* buffer = aes_encrypt((u_char*)out, sizeof(packet), client_aes_key, client_aes_iv, &size);
    if (send(client_socket, buffer, size, 0) == -1) {
        perror("send");
        term(true);
    }
    #else
    strncpy(p->type, "PVM", 4);
    strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
    char *buffer_noenc = p->serialize();
    //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
    if (send(client_socket, buffer_noenc, sizeof(packet), 0) == -1) {
        perror("send");
        term(true);
    }
    delete[] buffer_noenc;
    #endif
    delete p;
    
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
