/*
A header only C++ logging library for linux with color support
To enable color support compile with "COLORS" defenition
in g++: g++ code.cpp -o a.out -D COLORS
*/

#ifndef PIZLOG_H
#define PIZLOG_H
#include <string>
#include <ctime>
#include <syslog.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum type
{
    INFO = 0x01,
    I = 0x01,
    WARNING = 0x02,
    W = 0x02,
    ERROR = 0x03,
    E = 0x03,
    EMERG = 0x04,
    EE = 0x04,
};
// colors
#ifdef COLORS
#define background_color(r, g, b) ({static char res[1024]; sprintf(res, "\033[48;2;%d;%d;%dm", r, g, b); res;})
#define font_color(r, g, b)       ({static char res[1024]; sprintf(res, "\033[38;2;%d;%d;%dm", r, g, b); res;})
#define reset                     "\033[0;m"
#define clear                     "\033[2J\033[H"
#define clear_                    fprintf(stderr, "\033[2J\033[H" )

#define info(...) fprintf(stderr, "%s[!]%s ", font_color(0, 255, 0), reset);    fprintf(stderr, __VA_ARGS__, "\n")
#define warn(...) fprintf(stderr, "%s[?]%s ", font_color(255, 255, 0), reset);  fprintf(stderr, __VA_ARGS__, "\n")
#define err(...)  fprintf(stderr, "%s[x]%s ", font_color(255,0 , 0), reset);    fprintf(stderr, __VA_ARGS__, "\n")
#else 
#define info(...) fprintf(stderr, "[!] %s%c", __VA_ARGS__, '\n')
#define warn(...) fprintf(stderr, "[?] %s%c", __VA_ARGS__, '\n')
#define err(...)  fprintf(stderr, "[x] %s%c", __VA_ARGS__, '\n')
#endif

class Logger
{
    private:
        // get the current time
        std::string getTimestamp()
        {
            std::time_t t = std::time(nullptr);
            struct tm *tm_info = localtime(&t);
            char buffer[20];
            strftime(buffer, 20, "%Y-%m-%dT%H:%M:%S", tm_info);
            return std::string(buffer);
        }
        // file name
        std::string dName = "./LOG-" + getTimestamp() + ".log";
        std::string name;
        // file descriptor
        FILE* file = nullptr;
    public:
        // constructor, takes file path as argument
        Logger(const char* filePath) : name(filePath)
        {
            file = fopen(name.c_str(), "a");
            if(!file)
            {
                perror("File");
            }
            writelog<INFO, 1, 0>("Logger has been opened!");
        }
        
        Logger()
        {
            
        }
        // closes the file
        ~Logger()
        {
            if (file != nullptr)
            {
                writelog<WARNING, 1, 0>("Logger destroyed!");
                writelog<WARNING, 1, 0>("Logger will no longer work!");
                fclose(file);
                file = nullptr; // Set file to nullptr after closing
            }
        }
        // write log to the file
        //type t -> the type of the log (see the enum)
        //bool p -> should it print to the console
        //bool sys -> should it log the msg to the system log
        template<type t, int p, int sys>
        void writelog(const char *msg)
        {
            #ifndef USE_EMERG
            static_assert(!(t == EMERG), "You may avoid using EMERG unless it's something very important!\nDefine USE_EMERG to avoid this error!");
            #endif
            std::string logMsg = getTimestamp() + " ";
            switch (t)
            {
                case 0x01:
                    logMsg += "[INFO]";
                    break;
                case 0x02:
                    logMsg += "[WARNING]";
                    break;
                case 0x03:
                    logMsg += "[ERROR]";
                    break;
                case 0x04:
                    logMsg += "[EMERGENCY]";
                    break;
            }
            logMsg += " " + std::string(msg) + '\n';
            if (file == nullptr)
                fprintf(stderr, "Invalid file pointer");
            else fwrite (logMsg.c_str(), 1, logMsg.size(), file);
            fflush (file);
            switch (p)
            {
            case 1:
                switch (t)
                {
                    case 0x01:
                        info(logMsg.c_str());
                        break;
                    case 0x02:
                        warn(logMsg.c_str());
                        break;
                    case 0x03:
                        err(logMsg.c_str());
                        break;
                    case 0x04:
                        err(logMsg.c_str());
                        break;
                }
                break;
            default:
                break;
            }
            switch (sys)
            {
                case 0: // idk?
                case 1:
                    openlog("Pizzuhh's logger", LOG_PID | LOG_CONS, LOG_USER);
                    switch (t)
                    {
                        case 0x01:
                            syslog(LOG_INFO, "%s", logMsg.c_str());
                            break;
                        case 0x02:
                            syslog(LOG_WARNING, "%s", logMsg.c_str());
                            break;
                        case 0x03:
                            syslog(LOG_ERR, "%s", logMsg.c_str());
                            break;
                        case 0x04:
                            syslog(LOG_EMERG, "%s", logMsg.c_str());
                            break;
                    }
                
            }
        }
        /*
        Logs error using perror()
        */
        void logError() 
        {
            std::string logMsg = getTimestamp() + " [ERROR] ";
            perror("");
            logMsg += std::string(strerror(errno)) + '\n';

            // Write to the file
            fwrite(logMsg.c_str(), 1, logMsg.size(), file);
            fflush(file);
            err(logMsg.c_str());
        }
        void CloseLogger()
        {
            if (file != nullptr)
            {
                writelog<WARNING, 1, 0>("Logger closed!");
                writelog<WARNING, 1, 0>("Any calls to the logger won't be logged in the file!");
                fclose(file);
                file = nullptr;
            }
        }
        void DelteLog()
        {
            remove(name.c_str());
            info("Log file has been deleted!");
            CloseLogger();
        }
};


#endif // Pizzuhh's logger
