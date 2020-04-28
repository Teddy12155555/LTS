#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define IP "127.0.0.1"
#define PORT 8080
#define MAX 1024

SSL_CTX *ctx;
