# pizzeria
A basic chat app written in C++ using unix sockets. 

- [Features](#features)
- [Building](#building)

# Features
 - multithreaded
 - encryption (coming soon)
 - switch between TCP and UDP (coming soon)
 - colors (coming soon)
 - *GUI (probably)*

# Building
Firstly make sure you have [libuuid](https://linux.die.net/man/3/libuuid). Clone the repo `git clone https://github.com/pizzuhh/pizzeria.git` and run `make`. You'll see folder `build` in that folder there will be 2 files: `server` and `client`.

# Windows support?
Windows is currently not supported. It'll take some time to port the code to windows and to make sure that everything works. If you want to use it on windows, use [WSL](https://learn.microsoft.com/en-us/windows/wsl/)