FROM archlinux:latest
RUN pacman -Syu --noconfirm git gcc make
WORKDIR /app
RUN git clone -b main "https://github.com/pizzuhh/pizzeria.git" .
ADD https://api.github.com/repos/pizzuhh/pizzeria/git/refs/heads/main version.json
RUN git pull
RUN make
EXPOSE 5524
CMD ["./build/server", "--default-port"]
