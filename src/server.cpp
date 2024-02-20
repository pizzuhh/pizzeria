#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <iostream>
#include <pthread.h>
#include <uuid/uuid.h>
#include <algorithm>

#ifdef CRYPTO
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
unsigned char *key1, *key2;
void GenerateKeyPair(unsigned char** privateKey, unsigned char** publicKey)
{
    RSA* rsa = RSA_generate_key(2048, 65537, NULL,  NULL);
    // private key
    BIO* priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL);
    int privkeyLen = BIO_pending(priv_bio);
    *privateKey = (unsigned char*)calloc(privkeyLen + 1, 1);
    BIO_read(priv_bio, *privateKey, privkeyLen);

    // public key
    BIO* pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub_bio, rsa);
    int pubkeyLen = BIO_pending(pub_bio);
    *publicKey = (unsigned char*)calloc(pubkeyLen + 1, 1);
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
    return rsa;
}
unsigned char* Decrypt(const unsigned char* msg, RSA* key)
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
unsigned char* Encrypt(const unsigned char* msg, RSA* key)
{
    size_t len = strlen((const char*)msg);
    if (!key)
    {
        fprintf(stderr, "Public key is invalid!\n");
        exit(1);
    }
    unsigned char* encrypted = (unsigned char*)malloc(RSA_size(key));
    RSA_public_encrypt(len, msg, encrypted, key, RSA_PKCS1_PADDING);
    return encrypted;
}
#endif


using std::vector;

#define msleep(ms) usleep(ms * 1000);
struct client
{
    int fd;
    //int id;
    char id[1024];
    char uid[1024];
    sockaddr addr;
    bool valid = true;
    #ifdef CRYPTO
    char  plainTextKey[1024];
    RSA* publicKey;
    #endif 
};

vector<client*> clients;

void* handle_client(void* arg);
/*server admin client*/
void* server_client(void* arg);
void send_message(char* msg, char* sender);
void send_message(char *msg);
void broken_pipe()
{
    for (client* cl : clients)
    {
        if (fcntl(cl->fd, F_GETFD) != -1 || errno == EBADF)
        {
            fprintf(stderr, "%s: Connection terminated!\n", cl->id);
            vector<client*>::iterator it = std::find(clients.begin(), clients.end(), cl);
            if (it != clients.end())
            {
                clients.erase(it);
            }
            delete cl;
        }
    }
    fprintf(stderr, "Broken pipe has been detected! Could be that client has disconnected\n");
}



int main(void)
{
    #ifndef CRYPTO
    fprintf(stderr, "SERVER IS RUNNING WITHOUT ENCRYPTION!\nTO USE ENCRYPTION REBUILD THE SERVER AND THE CLIENT!\n");
    #endif
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    int port = 0;
    printf("Enter port (the port must not be used by other process! Default port is 5524): ");
    char input[7];
    if (fgets(input, 6, stdin) != NULL)
    {
        input[7] = '\0';
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
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1)
    {
        perror("socket");
        exit(-1);
    }
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port); 
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == -1)
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
    GenerateKeyPair(&key1, &key2);
    #endif
    pthread_t adminClient;
    pthread_create(&adminClient, 0, server_client, 0);
    while (true)
    {
        pthread_t p;
        int cl_fd = accept(fd, (sockaddr*)&cl_addr, (socklen_t*)&socklen);
        if (cl_fd > 0)
        {
            last_id++;
            client *cl = new client;
            cl->fd = cl_fd;
            cl->addr = cl_addr;
            //clients.push_back(cl);
            pthread_t p;
            pthread_create(&p, 0, handle_client, (void*)cl);
            
//            printf("Con: %d\n", clients.size());
        }
        else
            exit(-1);
    }
    
}
#define MAX_LEN 1024



void* parse_command(const std::string command)
{
    printf("NOT IMPLEMENTED!\n");
    return 0;
}

// should finish this
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
        send_message(const_cast<char*>(buff.c_str()));
    }
    
    return nullptr;
}

void send_message(char *msg, char *sender)
{
    for(const auto& client : clients)
    {
        if (strcmp(client->uid, sender))
        {
            char* out = new char[1024];
            snprintf(out, 1024, "%s: %s", sender, msg);
            #ifdef CRYPTO
            unsigned char* encrypted = Encrypt((const unsigned char*)out, client->publicKey);
            send(client->fd, encrypted, MAX_LEN, 0);
            #else
            send(client->fd, out, strlen(out), 0);
            #endif
        }
    }
}
void send_message(char *msg)
{
    for(const auto& client:clients)
    {

        char* out = new char[1024];
        #ifdef CRYPTO
        unsigned char* encrypted = Encrypt((const unsigned char*)out, client->publicKey);
        send(client->fd, encrypted, MAX_LEN, 0);
        #else
        sprintf(out, "%s: %s", "[SERVER]", msg);
        #endif
        send(client->fd, out, strlen(out), 0);
    }
}

void* handle_client(void* arg)
{
    char msg[MAX_LEN] = {0};
    client *cl = (client*)arg;
    char id_buff[1024];
    recv(cl->fd, id_buff, 1024, 0);
    memcpy(cl->id, id_buff, 1024); 
    char uid_buff[1024];
    recv(cl->fd, uid_buff, 1024, 0);
    memcpy(cl->uid, uid_buff, 1024);
    printf("client %s: has connected with uid of: %s\n", cl->id, cl->id);
    
    #ifdef CRYPTO
    // send public key
    send(cl->fd, key2, strlen((const char*)key2), 0);

    // receive public key
    char clientPublicKey[1024];
    recv(cl->fd, cl->plainTextKey, 1024, 0);
    cl->publicKey = LoadPublicKeyFromString((const char*)cl->plainTextKey);
    // load private key for decryption
    RSA* pkey = LoadPrivateKeyFromString((const char*)key1);

    #endif
    clients.push_back(cl);
    while(cl->valid)
    {
        int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        if (bytes <= 0)
            return 0;
        if (!strncmp(msg, "#!CLOSE", 7))
            cl->valid = false;
        #ifdef CRYPTO
        unsigned char* dec = Decrypt((const u_char*)&msg, pkey);
        printf("%s: %s\n", cl->uid, dec);
        send_message((char*)dec, cl->uid);
        #else
        printf("%s: %s\n", cl->uid, msg);
        send_message(msg, cl->uid);
        #endif
    }
    vector<client*>::iterator it = std::find(clients.begin(), clients.end(), cl);
    if (it != clients.end())
    {
        clients.erase(it);
    }
    delete cl;
    return 0;
}