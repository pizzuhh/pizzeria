/*
pizzeria web server client

This is the program that should be executed to connect with the webUI

scheme:

webUI (browser, the HTML page) -> webUI (server) -> server (pizzeria server)
*/

#include "helper.hpp"


void *handle_client(void* args)
{
    pweb_client cl = (pweb_client)args;
    char *buffer = new char[KiB(4)];
    while (1)
    {
        int fd = recv(cl->fd, buffer, sizeof(buffer), 0);
        if (fd > 0)
        {
            
            break;
        }
        else
            break;
    }
    memset(buffer, 0, sizeof(buffer));
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
                pthread_t p;
                pweb_client cl = new web_client;
                cl->fd = fd;
                pthread_create(&p, nullptr, handle_client, cl);
                pthread_detach(p);
            }
            else
            {
                continue;
            }
        }
        
    });
    s.start();
}
