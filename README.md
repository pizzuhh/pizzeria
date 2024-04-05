# pizzeria
A basic chat app written in C++ using unix sockets. 
### Note
The pre-built binaries are outdated most of the time so it's recommended to build the project yourself. Check [Building](#Building)
- [Features](#features)
- [Building](#building)
- [V2.5 release notes](#v25)

# Features
 - multithreaded
 - encryption
 - switch between TCP and UDP (coming soon)
 - colors (coming soon)

# Building
## Dependencies
- libuuid
- openssl
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

# 3.0
## Changes
- Private messages `#!pm <target> <message>`<br>
`<target>` -> username of the person you want to send private message
`<message>` -> The private message (note: everything after the first space is considered message)
- Usernames won't be able to have spaces (they'll be replaced by `-`)
- Servers now can disconnect clients (`#!kick` command may come in in 3.1)
- Colored messages (Linux only) may come in v3.1/3.2
- Plans on adding windows support (could happen in v4.0)
- GUI (planned for the summer. Maybe v5.0+)

## How to use the webUI?
Firstly build the server, client and the webUI server (ENCRYPTION MUST BE ENABLED). Make sure the webUI.html file is in the current working directory (run `pwd` to see it). Connect to the chat server and a random port will be opened (you'll see it on the terminal), now you can connect to the UI.
### endpoints
You can use the webUI as API to send automated messages too! Here are some endpoints:
- ``GET /`` - the UI
- ``GET /get`` - to get the messages (a bit broken). If no message is received, empty response will be returned
- ``POST /send`` - send a message
## Docker image for the server
If you want to run the server using docker:
1. Pull the docker image `docker pull pizzuhh/pizzeria-server`
2. Run it using `docker run -it -p 5524:5524 pizzeria-server`
3. To stop the server either press CTRL+C or CTRL+D
- Note
If you want to use different port change `p 5524:5524` part to `p custom-port:5524` (custom port being the port you wish)

You can send domain names (for example: chat.example.com) to your friends instead an IP
