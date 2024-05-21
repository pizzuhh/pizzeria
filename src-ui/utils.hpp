#include "../src/client.hpp"


int Ping(const char *ip, const int port) {
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return 0;
    }
    sockaddr_in server_addr = {0};
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;
    //server_addr.sin_addr.s_addr = inet_addr(ip);
    if (inet_pton(AF_INET, toIPv4(ip), &server_addr.sin_addr.s_addr) <= 0)
    {
        perror("inet_pton");
        return 0;

    }
    if (connect(client_socket, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr)) == -1)
    {
        perror("connect");
        return 0;
    }
    packet2 pingpacket("", "", "", packet_type::PING);
    char *data = pingpacket.serialize();
    send(client_socket, data, PACKET_SIZE, 0);
    char buffer[5];
    recv(client_socket, buffer, 5, 0);
    if (!strcmp(buffer, "PONG")) return 1;
    return 0;
}
