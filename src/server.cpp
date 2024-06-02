/*
server.cpp 

This file contains the code for the server side
written by: pizzuhh
*/
#include "server.hpp"
#include <sys/stat.h>

const char* jsonString = "{\n"
    "    \"filter\": {\n"
    "        \"enabled\": false,\n"
    "        \"mode\": 1,\n"
    "        \"max-clients\": 50,\n"
    "        \"filter\": [\n"
    "        ]\n"
    "    },\n"
    "    \"banned-clients\" : [\n"
    "    ],\n"
    "    \"admins\" : [\n"
    "    ]\n"
    "}";


int main(int argc, char **argv)
{
    #ifndef DISABLE_UPDATE_CHECK
    if (checkForUpdate()) {
        #ifdef DEBUG
        printf("%d\n", checkForUpdate());
        #endif
        printf("New update has been found!\nGo download it from: https://github.com/pizzuhh/pizzeria/releases/latest\n\n");
    }
    #endif
    cfg_path = getcfgpath();
    #ifdef DEBUG
    printf("%s\n", cfg_path);
    is_debug_enabled = 1;
    #endif
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
    if (logging || is_debug_enabled == 1) {
        if (logFile == nullptr) {
            time_t raw;
            struct tm *timeinfo;
            time(&raw);
            timeinfo = localtime(&raw);
            char time_str[1024];
            strftime(time_str, sizeof(time_str), "pizzeria-server-%Y-%m-%dT%H:%M:%S.log", timeinfo);
            logFile = time_str;
        }
        logger = new Logger(logFile);
    }
    if (is_debug_enabled == 1) WRITELOG(WARNING, "Logger forced by debug mode!");
    WRITELOG(INFO, "Reading config file.");
    int loaded = load_config();
    if (!loaded) {
        cfg.open(cfg_path, std::ios::app | std::ios::in | std::ios::out);
        if (!cfg.is_open()) {
            char *dir = (char*)strrchr(cfg_path, '/');
            if (!dir) {
                fputs("Can't do string stuff", stderr);
                abort();
            }
            *dir = '\0';
            mkdir(cfg_path, S_IRWXU | S_IRWXG | S_IRWXO);
            *dir = '/';
            cfg.open(cfg_path, std::ios::out | std::ios::app | std::ios::in);
            cfg.write(jsonString, strlen(jsonString));
            cfg.flush();
            chmod(cfg_path, S_IRWXU | S_IRWXG | S_IRWXO);
        }
        load_config();
    }
    WRITELOG(INFO, formatString("[CONFIG] filter status: %s", filter_on == 1 ? "ON" : "OFF"));
    WRITELOG(INFO, formatString("[CONFIG] filter mode: %s", filter_mode == DO_NOT_SEND_MESSAGE ? "DO_NOT_SEND_MESSAGE" : 
                                                            (filter_mode == KICK_USER ? "KICK_USER" : 
                                                            filter_mode == BAN_USER ? "BAN_USER" : "UNDEFINED")));
    // warn if the server is not running with encryption
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
    printf("Server listens on local port %d\n", port);
    if (listen(fd, 5) == -1) {
        perror("listen");
        LOGERROR();
        exit(-1);
    }
    WRITELOG(INFO, "Bind successful. Listening for connections");
    //int last_id = 0;
    sockaddr cl_addr;
    int socklen = sizeof(cl_addr);

    // generate private-public key pair
    generateAESKeys(server_aes_key, server_aes_iv);
    WRITELOG(INFO, "[CRYPTO]: Generated key pairs");
    pthread_t adminClient;
    pthread_create(&adminClient, 0, server_client, 0);
    WRITELOG(INFO, "Created server client thread");
    while (true) {
        pthread_t p;
        int cl_fd = accept(fd, (sockaddr *)&cl_addr, (socklen_t *)&socklen);
        if (cl_fd > 0) {
            WRITELOG(INFO, "Accepted connection");
            client *cl = new client;
            cl->fd = cl_fd;
            pthread_create(&p, 0, handle_client, (void *)cl);
            WRITELOG(INFO, "Created client thread");
        } else exit(-1);
    }
}
