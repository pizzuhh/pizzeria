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
#define MAX_LEN 500

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
    // handle ip later
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
    printf("Welcome to the chat room (%s:%d)\nYour unique ID is: %s", ip, port, uid);
    pthread_create(&t_recv, 0, rcv, 0);
    pthread_create(&t_send, 0, snd, 0);
    pthread_join(t_recv, 0);
    pthread_join(t_send, 0);
}

void *rcv(void *arg)
{
    char *buff = new char[MAX_LEN];
    while (running)
    {
        int bytes = recv(client_socket, buff, MAX_LEN, 0);
        if (bytes <= 0)
            continue;
        else
            printf("%s\n", buff);
        memset(buff, 0, MAX_LEN);
    }
    
    return nullptr;
}

void *snd(void *arg)
{
    std::string buffer;
    while (running)
    {
        std::getline(std::cin, buffer);
        if (send(client_socket, buffer.c_str(), MAX_LEN, 0) == -1)
        {
            perror("send");
            term();
        }
    }
    
    return nullptr;
}
