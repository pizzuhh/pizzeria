#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <uuid/uuid.h>
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




char* gen_uid()
{
    char* uid = new char[1024];
    uuid_t uidt;
    uuid_generate_time(uidt);
    uuid_unparse(uidt, uid);
    return uid;
}