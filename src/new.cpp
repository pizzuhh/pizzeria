enum class TYPE : char {
        MESSAGE = 0,
        PRIVATE_MESSAGE = 1,
        CLIENT_CLOSE = 2,
        SERVER_CLIENT_KICK = 3,
        AUTH = 4,
        GENERIC = 10
    };
struct packet2 {
     
    TYPE type;
    char sender[MAX_INPUT+1];
    char receiver[MAX_INPUT+1];
    char data[MAX_LEN];
    
};

void packet_init(packet2 *p, TYPE type, char *data, char *sender, char *receiver) {
    p->type = type;
    strncpy(p->data, data, MAX_LEN);
    strncpy(p->sender, sender, MAX_INPUT);
    strncpy(p->receiver, receiver, MAX_INPUT);
}
char *serialize(packet2 p) {
    char *ret = new char[sizeof(p)];
    memcpy(ret, p.data, sizeof(packet2::data));
    memcpy(ret + sizeof(packet2::data), p.receiver, sizeof(packet2::receiver));
    memcpy(ret + sizeof(packet2::data) + sizeof(packet2::receiver), p.sender, sizeof(packet2::sender));
    memcpy(ret + sizeof(packet2::data) + sizeof(packet2::receiver) + sizeof(packet2::sender), &p.type, sizeof(packet2::type));
    return ret;
}
packet2 deserialize(char *data) {
    packet2 *packet = new packet2;
    memcpy(packet->data, data, sizeof(packet2::data));
    memcpy(packet->receiver, data + sizeof(packet2::data), sizeof(packet2::receiver));
    memcpy(packet->sender, data + sizeof(packet2::data) + sizeof(packet2::receiver), sizeof(packet2::sender));
    memcpy(&packet->type, data + sizeof(packet2::data) + sizeof(packet2::receiver) + sizeof(packet2::sender), sizeof(packet2::type));
    return *packet;
}
