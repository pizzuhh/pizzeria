#pragma once
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
#include <map>
#include "genuuid.hpp"
#include <netdb.h>
#include <ctype.h>
#include <netinet/in.h>
#include <errno.h>
#include <sstream>
#include <curl/curl.h>
#include "json.hpp"
#include "config.h"
// for the encryption support
#ifdef CRYPTO
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void print_error_and_abort(void) {
    char err_msg[256];
    ERR_error_string_n(ERR_get_error(), err_msg, 256);
    fprintf(stderr, "%s\n", err_msg);
    abort();
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *client_privatekey = nullptr, *client_publickkey = nullptr;

int generateRsaKeys(EVP_PKEY **rsa_privKey, EVP_PKEY **rsa_pubKey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, nullptr);
    if (!ctx) handleErrors();
    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();
    if (EVP_PKEY_keygen(ctx, rsa_privKey) <= 0) handleErrors();
    *rsa_pubKey = EVP_PKEY_dup(*rsa_privKey);
    if (!*rsa_pubKey) handleErrors();
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int rsa_encrypt(u_char *plaintext, size_t plaintext_len, EVP_PKEY *publicKey, unsigned char **encrypted, size_t *encrypted_len) {
    EVP_PKEY_CTX *ctx;
    size_t outlen;
    int ret;

    // Create and initialize the context
    ctx = EVP_PKEY_CTX_new(publicKey, NULL);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0)
        handleErrors();

    // Determine buffer length
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char*)plaintext, plaintext_len) <= 0)
        handleErrors();

    *encrypted = (unsigned char*)malloc(outlen);
    if (!*encrypted)
        handleErrors();

    if (EVP_PKEY_encrypt(ctx, *encrypted, &outlen, (unsigned char*)plaintext, plaintext_len) <= 0)
        handleErrors();

    *encrypted_len = outlen;

    EVP_PKEY_CTX_free(ctx);
    return 1; // Success
}

int rsa_decrypt(unsigned char *encrypted, size_t encrypted_len, EVP_PKEY *privateKey, unsigned char **decrypted, size_t *decrypted_len) {
    EVP_PKEY_CTX *ctx;
    size_t outlen;
    int ret;

    // Create and initialize the context
    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
        handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        handleErrors();

    // Determine buffer length
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted, encrypted_len) <= 0)
        handleErrors();

    *decrypted = (unsigned char*)malloc(outlen);
    if (!*decrypted)
        handleErrors();

    if (EVP_PKEY_decrypt(ctx, *decrypted, &outlen, encrypted, encrypted_len) <= 0)
        handleErrors();

    *decrypted_len = outlen;

    EVP_PKEY_CTX_free(ctx);
    return 1; // Success
}

int serializeEVP_PKEY(EVP_PKEY *key, char **buffer) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return 0;

    if (!PEM_write_bio_PUBKEY(bio, key)) { // Use PEM_write_bio_PrivateKey for private keys
        BIO_free(bio);
        return 0;
    }

    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio, &bio_buf);
    *buffer = (char *)malloc(bio_buf->length + 1);
    if (!*buffer) {
        BIO_free(bio);
        return 0;
    }

    memcpy(*buffer, bio_buf->data, bio_buf->length);
    (*buffer)[bio_buf->length] = '\0';

    BIO_free(bio);
    return 1;
}

// Function to deserialize PEM formatted buffer to EVP_PKEY
EVP_PKEY *deserializeEVP_PKEY(const char *buffer) {
    BIO *bio = BIO_new_mem_buf(buffer, -1);
    if (!bio) {
        fprintf(stderr, "Error creating memory buffer\n");
        return NULL;
    }

    EVP_PKEY *key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL); // Use PEM_read_bio_PrivateKey for private keys
    if (!key) {
        fprintf(stderr, "Error reading PEM data\n");
        ERR_print_errors_fp(stderr); // Print OpenSSL error messages
        BIO_free(bio);
        return NULL;
    }

    BIO_free(bio);
    return key;
}



int generate_key_iv(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, 32) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Failed to generate key and IV.\n");
        return -1;
    }
    return 0;
}

unsigned char *aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    *ciphertext_len = plaintext_len + AES_BLOCK_SIZE; // allocate space for padding
    unsigned char *ciphertext = new u_char[*ciphertext_len];
    if (!ciphertext) handleErrors();

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    *ciphertext_len = len; // update the length with the bytes written

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();

    *ciphertext_len += len; // add the last block to the total length

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

unsigned char *aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    unsigned char *plaintext = new u_char[ciphertext_len]; // ciphertext length is maximum possible size of plaintext
    if (!plaintext) handleErrors();

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();

    *plaintext_len = len; // update the length with the bytes written

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors(); // note: decryption errors can occur if incorrect key/iv is used or if the ciphertext is tampered
    }

    *plaintext_len += len; // add the last block to the total length

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
/*
* returns the total size after the data is padded
*/
int calc_padding (int init_legnth) {
    int mod = init_legnth % AES_BLOCK_SIZE;
    return init_legnth + (AES_BLOCK_SIZE - mod);
}

u_char server_aes_key[32], server_aes_iv[AES_BLOCK_SIZE], client_aes_key[32], client_aes_iv[AES_BLOCK_SIZE];
#endif



using json = nlohmann::json;
size_t writeCallback(void *ptr, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size * nmemb;
    s->append((char*)ptr, newLength);
    return newLength;
    
}
/*
* @return 
* `-1`  -     check failed
* `0`   -     no update
* `1`   -     update available
*/
int checkForUpdate() {
    
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string buffer;
    
    curl_easy_setopt(curl, CURLOPT_URL, RELEASE_URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) return -1;
    std::string latestVersion;
    json j = json::parse(buffer);
    if (j.is_array()) {
        if (j.empty()) return -1;
        json el = j[0];
        latestVersion = el["tag_name"].get<std::string>();
    }
    if (latestVersion == VERSION) return 0;
    return 1;
}


#define MAX_LEN 1024
struct packet
{
    char type[4];
    char data[MAX_LEN];
    packet(const char *type, const char *data)
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
    /*packet to string*/
    char* serialize()
    {
        char* buffer = new char[sizeof(packet) + sizeof("\xff")];
        sprintf(buffer, "%s\xFF%s", this->type, this->data);
        return buffer;
    }
    /*string to packet*/
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

enum class packet_type : char {
        MESSAGE = 0,
        PRIVATE_MESSAGE = 1,
        CLIENT_CLOSE = 2,
        SERVER_CLIENT_KICK = 3,
        AUTH = 4,
        GENERIC = 10
};
#define PACKET_SIZE 1537
#define PADDED_PACKET_SIZE 1552

struct packet2 {
     
    packet_type type;
    char sender[MAX_INPUT+1];
    char receiver[MAX_INPUT+1];
    char data[MAX_LEN];
    packet2 (const char *data, const char *sender, const char *receiver, packet_type type) {
        this->type = type;
        strncpy(this->data,     data,       sizeof(this->data));
        strncpy(this->sender,   sender,     sizeof(this->sender));
        strncpy(this->receiver, receiver,   sizeof(this->receiver));
    }
    packet2 (packet_type type) {
        this->type = type;
    }
    packet2 (){}
    char* serialize() {
        size_t size = sizeof(this->type) + sizeof(this->receiver) + sizeof(this->sender) + sizeof(this->data);
        char* ret = new char[size];
        memcpy(ret, this, size);
        return ret;
    }
    static packet2 deserialize(char* data) {
        size_t size = sizeof(packet2::type) + sizeof(packet2::receiver) + sizeof(packet2::sender) + sizeof(packet2::data);
        packet2 packet;
        memcpy(&packet, data, size);
        return packet;
    }
};

bool isIp(const char* x)
{
    sockaddr_in sa;
    return inet_pton(AF_INET, x, &sa.sin_addr.s_addr) !=0;
}

char* toIPv4(const char* hostname)
{
    if (!isIp(hostname))
    {
        char* ip = new char[INET_ADDRSTRLEN];
        addrinfo hints = {0}, *result = {0};
        sockaddr_in *addr = {0};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int status = 0;
        if ((status = getaddrinfo(hostname, NULL, &hints, &result)))
        {
            fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
            abort();
        }
        addr = (sockaddr_in*)result->ai_addr;
        inet_ntop(AF_INET, &(addr->sin_addr.s_addr), ip, INET_ADDRSTRLEN);
        return ip;
    }
    return (char*)hostname;
}


bool iswhitespace (const char *str)
{
    while (*str)
    {
        if (!isspace(*str))
            return 0;
        str++;
    }
    
    return 1;
}


char* formatString(const char *format, ...)
{
    // Initialize a buffer to hold the formatted string
    const int bufferSize = 1024; // Adjust the size as needed
    char buffer[bufferSize];

    // Format the string using variable arguments
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, bufferSize, format, args);
    va_end(args);

    // Dynamically allocate memory for the formatted string
    char* formattedString = (char*)malloc(strlen(buffer) + 1);
    if (formattedString != nullptr)
    {
        strncpy(formattedString, buffer, strlen(buffer) + 1);
    }

    // Return the formatted string
    return formattedString;
}
/*
this function returns const char pointer allocated by malloc
make sure to free it using free()
*/
const char* format_string(const char* format, ...) 
{
    char *buffer = (char*)malloc(MAX_LEN * sizeof(char));
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, MAX_LEN * sizeof(char), format, args);
    va_end(args);
    return buffer;
}


std::vector<std::string> split(const std::string &str, const char del = ' ') 
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(str);
    while (std::getline(ss, token, del)) {
        tokens.push_back(token);
    }
    return tokens;
}


#define KiB(x) (x * 1024)
