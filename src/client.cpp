#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include <signal.h>
#include <limits.h>

#include "genuuid.h"
#define msleep(ms) usleep(ms * 1000);
#define MAX_LEN 1024

#ifdef CRYPTO
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
char pubkey[1024];
u_char *publicKey, *privateKey;
RSA* s2c_pubkey;
void GenerateKeyPair(u_char** privateKey, u_char** publicKey)
{
    RSA* rsa = RSA_generate_key(2048, 65537, NULL,  NULL);
    // private key
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL);
    int privkeyLen = BIO_pending(priv_bio);
    *privateKey = (u_char*)calloc(privkeyLen, 1);
    BIO_read(priv_bio, *privateKey, privkeyLen);

    // public key
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub_bio, rsa);
    int pubkeyLen = BIO_pending(pub_bio);
    *publicKey = (u_char*)calloc(pubkeyLen, 1);
    BIO_read(pub_bio, *publicKey, pubkeyLen);

    // printf("%s\n\n%s", *privateKey, *publicKey);
}
RSA* LoadPrivateKeyFromString(const char* privateKeyStr) 
{
    RSA* rsa = NULL;
    BIO* bio = BIO_new_mem_buf(privateKeyStr, -1);
    if (bio != NULL) 
    {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    return rsa;
}
RSA* LoadPublicKeyFromString(const char* publicKeyStr) 
{
    RSA* rsa = NULL;
    BIO* bio = BIO_new_mem_buf(publicKeyStr, -1);
    if (bio != NULL) 
    {
        rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    if (rsa == 0)
    {
        printf("??\n%s\n", publicKeyStr);
    }
    return rsa;
}
unsigned char *Decrypt(const unsigned char *msg, RSA *key)
{
    if (!key)
    {
        fprintf(stderr, "Private key is invalid!\n");
        exit(EXIT_FAILURE);
    }

    size_t len = RSA_size(key);
    unsigned char *decrypted = (unsigned char *)malloc(len);
    if (!decrypted)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    int dlen = RSA_private_decrypt(len, msg, decrypted, key, RSA_PKCS1_PADDING);
    if (dlen == -1)
    {
        ERR_print_errors_fp(stderr);
        // Handle decryption error
        fprintf(stderr, "Decryption failed!\n");
        free(decrypted);
        exit(EXIT_FAILURE);
    }

    decrypted[dlen] = '\0';

    return decrypted;
}
u_char* Encrypt(const u_char* msg, RSA* key)
{
    size_t len = strlen((const char*)msg);
    if (!key)
    {
        fprintf(stderr, "Public key is invalid!\n");
        exit(1);
    }
    u_char* encrypted = (u_char*)malloc(RSA_size(key));
    RSA_public_encrypt(len, msg, encrypted, key, RSA_PKCS1_PADDING);
    return encrypted;
}
#endif

struct packet
{
    char type[4];
    char data[MAX_LEN];
    packet(const char *type, char *data)
    {
        strncpy(this->type, type, 3);
        this->type[3] = '\0';
        strncpy(this->data, data, MAX_LEN);
    }
    packet(const char *type)
    {
        strncpy(this->type, type, 3);
        this->type[3] = '\0';
    }
    packet(){}
    char* serialize()
    {
        char* buffer = (char*)malloc(sizeof(packet) + sizeof("\xff"));
        sprintf(buffer, "%s\xFF%s", this->type, this->data);
        return buffer;
    }
    void deserialize(const char* in)
    {
        // Find the position of the delimiter '\xff'
        const char* delimiter = strchr(in, '\xff');

        // Ensure the delimiter is found and calculate the length
        if (delimiter != nullptr)
        {
            size_t typeLength = delimiter - in;
            size_t dataLength = strlen(delimiter + 1);

            // Copy type and data with appropriate lengths
            strncpy(this->type, in, typeLength);
            this->type[typeLength] = '\0'; // Null-terminate the type

            strncpy(this->data, delimiter + 1, dataLength);
            this->data[dataLength] = '\0'; // Null-terminate the data
        }
        else
        {
            // Handle the case where the delimiter is not found or the format is invalid
            // You may throw an exception, set default values, or handle it as appropriate for your application.
            fprintf(stderr, "Invalid input format in deserialize\n");
        }
    }
};


bool running = true;
int client_socket = 0;
pthread_t t_send, t_recv;


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
    strncpy(p.data, "", MAX_LEN);
    char* s = p.serialize();
    u_char* enc = Encrypt((const u_char*)s, s2c_pubkey);
    send(client_socket, enc, sizeof(packet), 0);
    pthread_detach(t_recv); pthread_detach(t_send);
    putc('\r', stdin);
    exit(0);
}

void* rcv(void* arg);
void* snd(void* arg);

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
    pthread_join(t_recv, 0);
    pthread_join(t_send, 0);
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
