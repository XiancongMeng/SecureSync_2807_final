// SecureSync/server/main.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket failed");
        exit(1);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        pid_t pid = fork();
        if (pid == 0) {
            // 子进程处理客户端
            printf("Client connected, child PID = %d\n", getpid());
            close(server_fd); // 子进程不需要监听 socket

            char buffer[1024] = {0};
            read(client_fd, buffer, sizeof(buffer));
            printf("Received: %s\n", buffer);
            close(client_fd);
            exit(0);
        } else if (pid > 0) {
            close(client_fd); // 父进程关闭连接 socket
        } else {
            perror("fork failed");
        }
    }

    return 0;
}

