#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void printAndAbort(void) {
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

int RSAEncrypt(u_char *plaintext, size_t plaintext_len, EVP_PKEY *publicKey, unsigned char **encrypted, size_t *encrypted_len) {
    EVP_PKEY_CTX *ctx;
    size_t outlen;

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

int RSADecrypt(unsigned char *encrypted, size_t encrypted_len, EVP_PKEY *privateKey, unsigned char **decrypted, size_t *decrypted_len) {
    EVP_PKEY_CTX *ctx;
    size_t outlen;

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



int generateAESKeys(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, 32) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Failed to generate key and IV.\n");
        return -1;
    }
    return 0;
}

unsigned char *AESEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, int *ciphertext_len) {
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

unsigned char *AESDecrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, int *plaintext_len) {
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
int calcPadding (int init_legnth) {
    int mod = init_legnth % AES_BLOCK_SIZE;
    return init_legnth + (AES_BLOCK_SIZE - mod);
}
