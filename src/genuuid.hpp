#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <string.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <string>


static std::string getCPUModelName() 
{
    std::ifstream cpuInfoFile("/proc/cpuinfo");

    if (!cpuInfoFile.is_open()) 
    {
        std::cerr << "Failed to open /proc/cpuinfo\n";
        return "Error";
    }

    std::string line;
    while (std::getline(cpuInfoFile, line)) 
    {
        if (line.find("model name") != std::string::npos) 
        {
            // Extract the CPU model name
            size_t pos = line.find(":");
            if (pos != std::string::npos) 
            {
                return line.substr(pos + 2); // Skipping ": " to get the actual name
            }
        }
    }

    return "Not found";
}

// get network card mac address
char* getMAC()
{
    // https://stackoverflow.com/questions/1779715/
    DIR* NICs = opendir("/sys/class/net/");
    struct dirent *dir;
    while ((dir = readdir(NICs))) {
        if (dir->d_type == DT_LNK) {
            if (!strncmp(dir->d_name, "en", 2)) {
                char path[MAX_INPUT+1];
                char* mac = (char*)malloc(18 * sizeof(char));
                snprintf(path, sizeof(path), "/sys/class/net/%s/address", dir->d_name);
                FILE* f = fopen(path, "r");
                size_t bytes = fread(mac, 1, 17, f);
                fclose(f);
                mac[bytes] = '\0';
                return mac;
            }
        }
    }
    return (char*)"00:00:00:00:00:00";
}
char* cpu_uuid()
{
    uuid_t cpu_uuid;
    std::string cpu = getCPUModelName();
    char* namespace1 = (char*)"cpuinfo";
    uuid_generate_md5(cpu_uuid, (const unsigned char*)namespace1, cpu.c_str(), cpu.size());
    char* buff = new char[1024];
    uuid_unparse(cpu_uuid, buff);
    return buff;
}

char* gen_priv_uuid()
{
    uuid_t mac_uuid;
    char *mac = getMAC();
    if (mac)
    {
        const unsigned char* ns = (const unsigned char*)"mac";
        uuid_generate_md5(mac_uuid, ns, mac, strlen(mac));
        char *buff = new char[1024];
        uuid_unparse(mac_uuid, buff);
        if (mac != nullptr) free(mac);
        return buff;
    }
    else
        return cpu_uuid();
}


char* gen_uid()
{
    char* uid = new char[1024];
    uuid_t uidt;
    uuid_generate_time(uidt);
    uuid_unparse(uidt, uid);
    return uid;
}
