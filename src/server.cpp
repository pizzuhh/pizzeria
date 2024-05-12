/*
server.cpp 

This file contains the code for the server side
written by: pizzuhh
*/
#include "server.hpp"
// main function
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
    WRITELOG(INFO, "Reading config file.");

    // parse the log file
    std::fstream cfg(DEFAULT_CFG_FILE_LOCATION);
    std::string cfg_data((std::istreambuf_iterator<char>(cfg)), std::istreambuf_iterator<char>());
    cfg.close();
    json _json = json::parse(cfg_data);
    filter_on       = _json["filter"]["enabled"];
    filter_mode     = _json["filter"]["mode"];
    if (_json["filter"]["filter"].is_array()) {
        for (const auto &item : _json["filter"]["filter"]) {
            words.append(item.get<std::string>() + "|");
        }
        if (!words.empty()) words.pop_back();
    }
    WRITELOG(INFO, formatString("[CONFIG] filter status: %s", filter_on == 1 ? "ON" : "OFF"));
    WRITELOG(INFO, formatString("[CONFIG] filter mode: %s", filter_mode == DO_NOT_SEND_MESSAGE ? "DO_NOT_SEND_MESSAGE" : 
                                                            (filter_mode == KICK_USER ? "KICK_USER" : 
                                                            filter_mode == BAN_USER ? "BAN_USER" : "UNDEFINED")));
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
    printf("Server listens on local port %d\n", port);
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
    generate_key_iv(server_aes_key, server_aes_iv);
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
