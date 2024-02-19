#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include <signal.h>
#include "genuuid.h"
#define msleep(ms) usleep(ms * 1000);
#define MAX_LEN 1024

#ifdef CRYPTO
#include <openssl/rsa.h>
#include <openssl/pem.h>
char pubkey[1024];
u_char *publicKey, *privateKey;
void GenerateKeyPair(u_char** privateKey, u_char** publicKey)
{
    RSA* rsa = RSA_generate_key(2048, 65537, NULL,  NULL);
    // private key
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL);
    int privkeyLen = BIO_pending(priv_bio);
    *privateKey = (u_char*)calloc(privkeyLen + 1, 1);
    BIO_read(priv_bio, *privateKey, privkeyLen);

    // public key
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub_bio, rsa);
    int pubkeyLen = BIO_pending(pub_bio);
    *publicKey = (u_char*)calloc(pubkeyLen + 1, 1);
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
u_char* Decrypt(const unsigned char* msg, RSA* key)
{
    if (!key)
    {
        fprintf(stderr, "Private key is invalid!\n");
        exit(1);
    }
    size_t len = RSA_size(key);
    u_char* decrypted = (u_char*)malloc(RSA_size(key));
    size_t dlen = RSA_private_decrypt(len, msg, decrypted, key, RSA_PKCS1_PADDING);
    if (dlen == -1)
    {
        // Handle decryption error
        fprintf(stderr, "Decryption failed!\n");
        free(decrypted);
        exit(1);
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


bool running = true;
int client_socket = 0;
pthread_t t_send, t_recv;


void term()
{
    running = false;
    send(client_socket, "#!CLOSE", 7, 0);
    close(client_socket);
    pthread_detach(t_recv); pthread_detach(t_send);
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
    msleep(10);
    send(client_socket, uid, 1024, 0);
    #ifdef CRYPTO
    recv(client_socket, pubkey, 1024, 0);
    // send client's public key so we can encrypt the message later
    send(client_socket, publicKey, 1024, 0);
    // printf("%s\n", pubkey);
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
            #ifdef CRYPTO
            u_char* decrypted = Decrypt((const u_char*)buff, privkey);
            printf("%s\n", decrypted);
            #else
            printf("%s\n", buff);
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
        if (std::cin.eof())
            term();
        std::getline(std::cin, msg);
        #ifdef CRYPTO
        u_char* buffer = Encrypt((const u_char*)msg.c_str(), pkey);
        if (send(client_socket, buffer, MAX_LEN, 0) == -1)
        {
            perror("send");
            term();
        }
        #else
        if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
        {
            perror("send");
            term();
        }
        #endif
        
    }
    
    return nullptr;
}
