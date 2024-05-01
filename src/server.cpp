/*
server.cpp 

This file contains the code for the server side
written by: pizzuhh
*/
#include "server.hpp"

// main function
int main(int argc, char **argv)
{
    if (checkForUpdate()) {
        printf("New update has been found!\nGo download it from: https://github.com/pizzuhh/pizzeria/releases/latest\n\n");
    }
    struct option opt[] = {
        {"log", optional_argument, 0, 'l'},
        {"default-port", no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };
    int c = -1;
    while ((c = getopt_long(argc, argv, "dl:", opt, 0)) != -1) {   
        switch (c)
        {
        case 'd':
            defaultPort = true;
            break;
        case 'l':
            logging = true;
            if (optarg) {
                logFile = optarg;
            }
            else {
                time_t raw;
                struct tm *timeinfo;
                char time_str[1024];

                time(&raw);
                timeinfo = localtime(&raw);
                strftime(time_str, sizeof(time_str), "pizzeria-server-%Y-%m-%dT%H:%M:%S.log", timeinfo);
                logFile = time_str;
            }
            printf("%s\n", logFile);
        default:
            break;
        }
    }
    if (logging) {
        logger = new Logger(logFile);
    }
    // warn if the server is not running with encryption
    #ifndef CRYPTO
    fprintf(stderr, "SERVER IS RUNNING WITHOUT ENCRYPTION!\nTO USE ENCRYPTION REBUILD THE SERVER AND THE CLIENT!\n");
    #endif
    signal(SIGPIPE, (sighandler_t)broken_pipe);
    WRITELOG(INFO, "SIGPIPE -> broken_pipe()");
    signal(SIGINT, (sighandler_t)cls);
    WRITELOG(INFO, "SIGINT -> cls()");
    signal(SIGSEGV, segfault_handler);
    WRITELOG(INFO, "SIGSEGV -> segfault_handler()");
    int port = 0;
    if (argc >= 2) {
        if (defaultPort) {
            port = 5524;
            WRITELOG(INFO, "Default port used: 5524");

        } else {
            printf("Enter port (the port must not be used by other process! Default port is 5524): ");
            char input[7];
            if (fgets(input, 6, stdin) != NULL) {
                // input[7] = '\0';
                if (input[0] == '\0')
                    port = 5524;
                else {
                    sscanf(input, "%d", &port);
                }
            }
            if (port == 0) {
                port = 5524;
            }
        }
    } else {
        printf("Enter port (the port must not be used by other process! Default port is 5524): ");
        char input[7];
        if (fgets(input, 6, stdin) != NULL) {
            // input[7] = '\0';
            if (input[0] == '\0')
                port = 5524;
            else {
                sscanf(input, "%d", &port);
            }
        }
        if (port == 0) {
            port = 5524;
        }
    }
    /*
    following code creates a socket, binds to it and listens for connections
    */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        LOGERROR();
        exit(-1);
    }
    WRITELOG(INFO, "socket()");
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (int *)1, sizeof(int));
    WRITELOG(INFO, "setsockopt()");
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    WRITELOG(INFO, "initialized sockaddr_in addr");
    if (bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == -1) {
        perror("bind");
        LOGERROR();
        exit(-1);
    }
    printf("Server listens on 127.0.0.1:%d\n", port);
    if (listen(fd, 5) == -1) {
        perror("listen");
        LOGERROR();
        exit(-1);
    }
    WRITELOG(INFO, "Bind successful. Listening for connections");
    int last_id = 0;
    sockaddr cl_addr;
    int socklen = sizeof(cl_addr);

    #ifdef CRYPTO
    // generate private-public key pair
    GenerateKeyPair(&private_key_gen, &public_key_gen);
    s_pubkey = LoadPublicKeyFromString((const char*)public_key_gen);
    s_privkey = LoadPrivateKeyFromString((const char*)private_key_gen);
    WRITELOG(INFO, "[CRYPTO]: Generated key pairs");
    #endif
    pthread_t adminClient;
    pthread_create(&adminClient, 0, server_client, 0);
    WRITELOG(INFO, "Created server client thread");
    while (true) {
        pthread_t p;
        int cl_fd = accept(fd, (sockaddr *)&cl_addr, (socklen_t *)&socklen);
        if (cl_fd > 0) {
            WRITELOG(INFO, "Accepted connection");
            last_id++;
            client *cl = new client;
            cl->fd = cl_fd;
            cl->addr = cl_addr;
            // clients.push_back(cl);
            pthread_create(&p, 0, handle_client, (void *)cl);
            WRITELOG(INFO, "Created client thread");
        } else exit(-1);
    }
}
