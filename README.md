# pizzeria
A basic chat app written in C++ using unix sockets. 
### Note
The pre-built binaries are outdated most of the time so it's recommended to build the project yourself. Check [Building](#Building)
- [Features](#features)
- [Building](#building)
- [3.4 Change log](#34)

# Contributing
Read [CONTRIBUTING.md](CONTRIBUTING.md) for more information
# Features
- multithreaded
- encryption
- switch between TCP and UDP (coming soon)
- colors (coming in v3.1/3.2, only for linux)
- Plans on adding windows support (could happen in v4.0)
- GUI (planned for the summer. Maybe v4.0+)


# Building
## Dependencies
- libuuid
- openssl
- libnotify (not needed for now)
- libcurl
- [JSON for modern C++](https://github.com/nlohmann/json) (it's included in src/ directory so no need to download it)
## Building
Run the following commands to build the project. If there are any issues make an issue!
1. `$ git clone https://github.com/pizzuhh/pizzeria`
2. `make`
3. The binaries are in `./build`

# Windows support?
Windows is currently not supported. It'll take some time to port the code to windows and to make sure that everything works. If you want to use it on windows, use [WSL(Windows Subsystem for Linux)](https://learn.microsoft.com/en-us/windows/wsl/)

# Custom clients
For now the original client is supported. In order to create a client you must:
- Generate RSA key pairs, 2048bit with RSA_PKCS1_PADDING
- Generate unique UUID for the device (mustn't change)
- Generate unique UUID for the session (should be different every-time, or not)
- Receive the public key from the server (if you want to support encryption)
- Send the public key to the server (if you want to support encryption)
### ALL OF THESE MUST BE MANE IN THIS ORDER
After that you need to create 3 threads:
1. receiver (receive messages from the server)
2. sender (send messages to the server)
3. heartbeat (every second send `HRT` packet to the server)

# 3.4
## Changes
- Moved to AES.
- New packet system.
- Logging hashed ips. (Needed for bans)
## The filter
The filter is configured by `server-cfg.json`.

`enabled` - true - the filter is enabled or false - the filter is disabled

`mode` - 0 - Messages won't be send, 1 - The message won't be send and the user will be kicked, 2 - The message won't be send and the user will be banned (banning is not implemented yet)

`filter` - JSON array of the words you want to filter. <b>DO NOT LEAVE THIS EMPTY IF `enabled` IS SET TO `true`.</b> (please the remove the placeholder words).

# Docker image for the server
If you want to run the server using docker:
1. Pull the docker image `docker pull pizzuhh/pizzeria-server`
2. Run it using `docker run -it -p 5524:5524 pizzeria-server`
3. To stop the server either press CTRL+C or CTRL+D
- Note
If you want to use different port change `p 5524:5524` part to `p custom-port:5524` (custom port being the port you wish)

You can send domain names (for example: chat.example.com) to your friends instead an IP
