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
#include <limits.h>
#include <stdarg.h>

#ifdef CRYPTO
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

unsigned char *private_key_gen, *public_key_gen;
RSA *s_pubkey, *s_privkey;
void GenerateKeyPair(unsigned char **privateKey, unsigned char **publicKey)
{
    RSA *rsa = RSA_generate_key(2048, 65537, NULL, NULL);
    // private key
    BIO *priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(priv_bio, rsa, NULL, NULL, 0, NULL, NULL);
    int privkeyLen = BIO_pending(priv_bio);
    *privateKey = (unsigned char *)calloc(privkeyLen, 1);
    BIO_read(priv_bio, *privateKey, privkeyLen);

    // public key
    BIO *pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(pub_bio, rsa);
    int pubkeyLen = BIO_pending(pub_bio);
    *publicKey = (unsigned char *)calloc(pubkeyLen, 1);
    BIO_read(pub_bio, *publicKey, pubkeyLen);

    // printf("%s\n\n%s", *privateKey, *publicKey);
}

RSA *LoadPrivateKeyFromString(const char *privateKeyStr)
{
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(privateKeyStr, -1);
    if (bio != NULL)
    {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
        BIO_free(bio);
    }
    return rsa;
}
RSA *LoadPublicKeyFromString(const char *publicKeyStr)
{
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(publicKeyStr, -1);
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


unsigned char *Encrypt(const unsigned char *msg, RSA *key)
{
    size_t len = strlen((const char *)msg);
    if (!key)
    {
        fprintf(stderr, "Public key is invalid!\n");
        exit(1);
    }
    unsigned char *encrypted = (unsigned char *)malloc(RSA_size(key));
    RSA_public_encrypt(len, msg, encrypted, key, RSA_PKCS1_PADDING);
    return encrypted;
}
#endif

#define MAX_LEN 1024
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
        if (type)
        {
            strncpy(this->type, type, 3);
            this->type[3] = '\0';
        }
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
            strncpy(type, in, 3);
            fprintf(stderr, "Invalid input format in deserialize\n");
        }
    }
};

using std::vector;

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

void *handle_client(void *arg);
/*server admin client*/
void *server_client(void *arg);
void send_message(char *msg, char *sender);
void send_message(const char *msg);
void fsend_message(char *fmt, ...);
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
    fprintf(stderr, "Broken pipe has been detected! Could be that client has disconnected\n");
}

void segfault_handler(int signo);
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

int main(void)
{
#ifndef CRYPTO
    fprintf(stderr, "SERVER IS RUNNING WITHOUT ENCRYPTION!\nTO USE ENCRYPTION REBUILD THE SERVER AND THE CLIENT!\n");
#endif
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    signal(SIGINT, (sighandler_t)cls);
    int port = 0;
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
            pthread_t p;
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
    char msg[MAX_LEN] = {0};
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
            fsend_message("%s: has disconnected", cl->uid);
            break;
        }
        // printf("%p\n", p->data);
/*         strncpy(msg, p.data, MAX_LEN);
        unsigned char *dec = Decrypt((const unsigned char*)&msg, s_privkey); */
        printf("%s: %s\n", cl->uid, p.data);
        send_message((char *)p.data, cl->uid);
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
    // Continue with the default signal handler for SIGSEGV
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}
