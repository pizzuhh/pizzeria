FROM archlinux:latest
RUN pacman -Syu --noconfirm git gcc make
WORKDIR /app
ARG BRANCH=main
RUN git clone -b $BRANCH "https://github.com/pizzuhh/pizzeria.git" .
RUN git pull
RUN make
EXPOSE 5524
CMD ["./build/server", "--default-port"]
