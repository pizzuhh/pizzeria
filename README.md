# pizzeria
A basic chat app written in C++ using unix sockets. 

- [Features](#features)
- [Building](#building)
- [V2-5 release notes](#v2-testing)

# Features
 - multithreaded
 - encryption
 - switch between TCP and UDP (coming soon)
 - colors (coming soon)

# Building
Firstly make sure you have [libuuid](https://linux.die.net/man/3/libuuid). Clone the repo `git clone https://github.com/pizzuhh/pizzeria.git` and run `make`. You'll see folder `build` in that folder there will be 2 files: `server` and `client`.

make commands:
`make` - builds the default binaries
`make build-no-encrypt` - builds the binaries without encryption enabled

# Windows support?
Windows is currently not supported. It'll take some time to port the code to windows and to make sure that everything works. If you want to use it on windows, use [WSL(Windows Subsystem for Linux)](https://learn.microsoft.com/en-us/windows/wsl/)

# V2.5-testing
## Added
- webUI for the client (a bit broken but works)
## To be fixed
- Server crashing when exiting from the webUI server
## How to use the webUI?
Firstly build the server, client and the webUI server (ENCRYPTION MUST BE ENABLED). Make sure the webui.html file is in the current working directory (run `pwd` to see it). Connect to the chat server and a random port will be opened (you'll see it on the terminal), now you can connect to the UI.
### endpoints
You can use the webui as API to send automated messages too! Here are some endpoints:
- ``GET /`` - the UI
- ``GET /get`` - to get the messages (a bit broken). If no message is received, empty response will be returned
- ``POST /send`` - send a message
