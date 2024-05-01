#include  "helper.hpp"
#include "client.hpp"
//#include <libnotify/notify.h>
/*Main function:
 * generates key pairs
 * connects to server
 * sends required data
 */
int main()
{
    if (checkForUpdate()) {
        #ifdef DEBUG
        printf("%d\n", checkForUpdate());
        #endif
        printf("New update has been found!\nGo download it from: https://github.com/pizzuhh/pizzeria/releases/latest\n\n");
    }
    //notify_init("pizzeria - client");
    #ifndef CRYPTO
    fprintf(stderr, "CLIENT IS RUNNING WITHOUT ENCRYPTION!\nTo connect with server(s) that use encryption, use client that supports it!\n");
    #endif
    signal(SIGINT, (sighandler_t)term);
    signal(SIGKILL, (sighandler_t)term);
    signal(SIGTERM, (sighandler_t)term);
    printf("Enter server ip and port (default is 127.0.0.1:5524): ");
    std::string addr = "";
    std::getline(std::cin, addr);
    if (addr.empty())
        addr = "127.0.0.1:5524";
    char ip[MAX_INPUT+1] = {0};
    int port = 0;
    if (sscanf(addr.c_str(), "%255[^:]:%d", ip, &port) != 2) 
    {
        fprintf(stderr, "Invalid input format\n");
        term(true);
    }

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        term(true);
    }
    sockaddr_in server_addr = {0};
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    //server_addr.sin_addr.s_addr = inet_addr(ip);
    if (inet_pton(AF_INET, toIPv4(ip), &server_addr.sin_addr.s_addr) <= 0)
    {
        perror("inet_pton");
        term(true);

    }
    #ifdef CRYPTO
    // generate public and private key
    
    GenerateKeyPair(&privateKey, &publicKey);
    #endif
    if (connect(client_socket, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
    {
        perror("connect");
        term(true);
    }
    
    // send server info
    const char* id    = gen_priv_uuid();
    //const char* uid   = gen_uid();
    char *username = new char[MAX_INPUT];
    while (1)
    {
        printf("Enter username: ");
        fflush(stdout);

        fgets(username, MAX_INPUT, stdin);
        size_t len = strlen(username);
        username[len-1] = '\0';
        if (len == 0 || iswhitespace(username))
            fprintf(stderr, "Invalid username please try again!\n");
        else
        {
            for (int i = 0; i < strlen(username); i++)
                if (username[i] == ' ') username[i] = '-';
            break;
        }
    }

    send(client_socket, id, 1024, 0);
    delete[] id;
    // msleep(10); // if something brakes uncomment this
    send(client_socket, username, MAX_INPUT, 0);
    
    #ifdef CRYPTO
    // receive server's public key
    recv(client_socket, pubkey, 1024, 0);
    // send client's public key so we can encrypt the message later
    send(client_socket, publicKey, 1024, 0);
    // printf("%s\n", pubkey);
    c2s_pubkey = LoadPublicKeyFromString(pubkey);
    #endif
    printf("Welcome to the chat room (%s:%d)\n", ip, port);
    delete[] username;
    connected = true;
    pthread_create(&t_recv, 0, rcv, 0);
    pthread_create(&t_send, 0, snd, 0);
    pthread_join(t_recv, 0);
    pthread_join(t_send, 0);
}
