FROM archlinux:latest
RUN pacman -Syu --noconfirm git gcc make
WORKDIR /app
COPY . .
RUN make
EXPOSE 5524
CMD ["./build/server", "--default-port", "--log"]
