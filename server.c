#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SRV_PORT 5000

int main(void) {
    struct sockaddr_in srv_addr, cli_addr;
    struct sockaddr_in cli_addr;

    char password[1000] = { 0 };

    size_t cli_addr_len = 0;

    int sockfd = -1;

    fprintf(stdout, "Starting server...\n");

    memset(&srv_addr, 0, sizeof(srv_addr));
    memset(&cli_addr, 0, sizeof(cli_addr));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons(SRV_PORT);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        exit(1);
    }

    if (bind(sockfd, (struct sockaddr*) &srv_addr, sizeof(srv_addr)) < 0)
    {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        exit(1);
    }

    fprintf(stdout, "Waiting for password...\n");

    while(1)
    {
        bzero(password, sizeof(password));

        if (recvfrom(sockfd, password, sizeof(password), 0, (struct sockaddr*) &cli_addr, &cli_addr_len) < 0)
        {
            fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
            exit(1);
        }

        fprintf(stdout, "Received password: %s\n", password);
    }

    close(sockfd);

    return 0;
}