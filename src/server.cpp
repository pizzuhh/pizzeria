#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>
#include <string>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <iostream>
#include <pthread.h>
#include <uuid/uuid.h>
#include <algorithm>

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
};

vector<client*> clients;

void* handle_client(void* arg);
/*server admin client*/
void* server_client(void* arg);
void send_message(char* msg, char* sender);
void send_message(char *msg);
void broken_pipe()
{
    fprintf(stderr, "Broken pipe has been detected! Could be that client has disconnected\n");
}

int main(void)
{
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    int port = 0;
    printf("Enter port (the port must not be used by other process! Default port is 5524): ");
    scanf("%5[^\n]", &port);
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
    
    while (true)
    {
        pthread_t p;
        pthread_t adminClient;
        int cl_fd = accept(fd, (sockaddr*)&cl_addr, (socklen_t*)&socklen);
        if (cl_fd > 0)
        {
            last_id++;
            client *cl = new client;
            cl->fd = cl_fd;
            cl->addr = cl_addr;
            clients.push_back(cl);
            pthread_t p;
            pthread_create(&p, 0, handle_client, (void*)cl);
            pthread_create(&adminClient, 0, server_client, 0);
//            printf("Con: %d\n", clients.size());
        }
        else
            exit(-1);
    }
    
}
#define MAX_LEN 500

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
    for(const auto& client:clients)
    {
        if (strcmp(client->uid, sender))
        {
            char* out = new char[1024];
            sprintf(out, "%s: %s", sender, msg);
            send(client->fd, out, strlen(out), 0);
        }
    }
}
void send_message(char *msg)
{
    for(const auto& client:clients)
    {
        char* out = new char[1024];
        sprintf(out, "%s: %s", "[SERVER]", msg);
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
    printf("client %s: has connected", cl->id);
    
    char uid_buff[1024];
    recv(cl->fd, uid_buff, 1024, 0);
    memcpy(cl->uid, uid_buff, 1024);
    printf(" with uid of: %s\n", cl->id);
    
    while(cl->valid)
    {
        int bytes = recv(cl->fd, msg, MAX_LEN, 0);
        if (bytes <= 0)
            return 0;
        if (!strncmp(msg, "#!CLOSE", 7))
            cl->valid = false;
        printf("%s: %s\n", cl->uid, msg);
        send_message(msg, cl->uid);
    }
    vector<client*>::iterator it = std::find(clients.begin(), clients.end(), cl);
    if (it != clients.end())
    {
        clients.erase(it);
    }
    delete cl;
    return 0;
}