/*
pizzeria web server client

This is the program that should be executed to connect with the webUI

scheme:

webUI (browser, the HTML page) -> webUI (server) -> server (pizzeria server)
*/

#include "helper.hpp"



bool running = true;
int client_socket = 0;
pthread_t t_send, t_recv, t_hrt;
char pubkey[1024];
u_char *publicKey, *privateKey;
#ifdef CRYPTO
RSA* s2c_pubkey;
#endif

char *currentmsg = nullptr;

void *rcv(void *arg)
{
    pweb_client cl = (pweb_client)arg;
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
            currentmsg = strdup(p->data);
            printf("%s\n", p->data);
            #else
            memcpy(&p, buff, sizeof(packet));
            printf("%s\n", p->data);
            #endif
            delete p;
        }
        memset(buff, 0, MAX_LEN);
    }
    
    return nullptr;
}


void *snd(std::string msg)
{
    #ifdef CRYPTO
    RSA* pkey = LoadPublicKeyFromString(pubkey);
    #endif
    packet *p = new packet;
    #ifdef CRYPTO
    strncpy(p->data, (char*)msg.c_str(), MAX_LEN);
    strncpy(p->type, "MSG", 4);
    char* out = p->serialize();
    u_char* buffer = Encrypt((const unsigned char*)out, pkey);
    if (send(client_socket, buffer, sizeof(packet), 0) == -1)
    {
        perror("send");
        exit(-1);
    }
    #else
    strncpy(p->type, "MSG", sizeof(p->type));
    strncpy(p->data, msg.c_str(), MAX_INPUT);
    //if (send(client_socket, msg.c_str(), MAX_LEN, 0) == -1)
    if (send(client_socket, p, MAX_LEN, 0) == -1)
    {
        perror("send");
        exit(-1);
    }
    #endif
    delete p;
    
    return nullptr;
}

char* uid;
char* id;
void handle_post_request(pweb_client cl) 
{
    if (!strncmp(cl->get_req_path(), "/send", strlen("/send"))) 
    {
        snd(cl->get_req_body());
        cl->send_response("200", "Content-Type: text/plain", "Message was sent!");
        return;
    } 
    else 
    {
        cl->send_response("404", "Content-Type: text/plain", "Not found");
        return;

    }
}
uint port = 0;
void handle_get_request(pweb_client cl) 
{
    if (!strcmp(cl->get_req_path(), "/")) 
    {
        std::map<const char*, const char*> arg;
        arg.insert(std::make_pair("$$PUUID$$", uid));
        arg.insert(std::make_pair("$$PORT$$", std::to_string(port).c_str()));
        const char *html = genHTML("./webui.html", arg);
        cl->send_response("200", "Content-Type: text/html", html);
        return;

    }
    else if (!strncmp(cl->get_req_path(), "/send", strlen("/send"))) 
    {
        snd(cl->get_req_body());
        cl->send_response("403", "Content-Type: text/plain", "Forbidden");
        return;

    } 
    else if (!strncmp(cl->get_req_path(), "/get", strlen("/get")))
    {
        if (currentmsg != nullptr)
        {
            cl->send_response("200", "Content-Type: text/plain\r\n" + std::string(CORSH), currentmsg);
        }
        else
            cl->send_response("200", "");
        free(currentmsg);
        currentmsg = nullptr;
        return;
    }
    else 
    {
        cl->send_response("404", "Content-Type: text/plain", "Not found");
        return;

    }
}

void *handle_client(void* args) 
{
    pweb_client cl = (pweb_client)args;
    char *buffer = new char[KiB(4)];
    while (1) 
    {
        int fd = recv(cl->fd, buffer, KiB(4), 0);
        if (fd > 0) 
        {
            cl->req = strdup(buffer);
            http htp = cl->get_req();
            if (!strcmp(htp.type, "POST")) 
            {
                handle_post_request(cl);
                break;
            } else if (!strcmp(htp.type, "GET")) 
            {
                handle_get_request(cl);
                break;
            }
        }
        else 
        {
            break;
        }
    }
    close(cl->fd);
    memset(buffer, 0, KiB(4));
    delete cl;
    return nullptr;
}

int main()
{
    server s(0, [](pserverinfo si)
    {
        while (1)
        {
            pthread_t p;
            int fd = -1;
            fd = accept(si->fd, nullptr, nullptr);
            if (fd > 0)
            {
                pthread_t p, t_rcv;
                pweb_client cl = new web_client;
                cl->fd = fd;
                pthread_create(&t_rcv, nullptr, rcv, cl);
                pthread_create(&p, nullptr, handle_client, cl);

                pthread_detach(p);
                pthread_detach(t_rcv);
            }
            else
            {
                continue;
            }
        }
        
    });
    port = s.port;
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
        return 1;
    }

    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(-1);
    }
    sockaddr_in server_addr = {0};
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, toIPv4(ip), &server_addr.sin_addr.s_addr) <= 0)
    {
        perror("inet_pton");
        abort();
    }
    // server_addr.sin_addr.s_addr = inet_addr(ip);
    #ifdef CRYPTO
    // generate public and private key
    
    GenerateKeyPair(&privateKey, &publicKey);
    #endif
    if (connect(client_socket, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
    {
        perror("connect");
        exit(-1);
    }

    // send server info
    id    = cpu_uuid();
    uid   = gen_uid();
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
    
    s.start();
}
