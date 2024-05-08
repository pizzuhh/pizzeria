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
    int dlen = RSA_private_decrypt(len, msg, decrypted, key, RSA_PKCS1_PADDING);
    if (dlen == -1)
    {
        // Handle decryption error
        fprintf(stderr, "Decryption failed!\n");
        free(decrypted);
        return nullptr;
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



using json = nlohmann::json;
size_t writeCallback(void *ptr, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size * nmemb;
    s->append((char*)ptr, newLength);
    return newLength;
    
}
/*
* @return 
* `-1` - check failed
* `0` - no update
* `1` - update available
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

struct packet_test {
    uint8_t type;
    char data[1024];
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
        strcpy(formattedString, buffer);
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
