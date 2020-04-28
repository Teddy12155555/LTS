
#include "Share.h"
#define CA "./CA.pem"
#define SERVER_KEY "./server-key.pem"
#define SERVER_CERT "./Server-cert.pem"

void Chat(SSL *ssl)
{
    while (1)
    {
        char buff[MAXBUF];
        int n;
        while (1)
        {
            bzero(buff, sizeof(buff));
            SSL_read(ssl, buff, MAXBUF);
            printf("From client: %s\t To client : ", buff);
            bzero(buff, sizeof(buff));

            if (strncmp("file", buff, 4) == 0)
            {
                char fileName[50] = "/newfile/";
                mode_t mode;

                mkdir("/newfile", mode);
                bzero(buff, sizeof(buff));
                bzero(fileName + 9, 42);
                int len = SSL_read(ssl, buff, MAXBUF);
                if (len == 0)
                {
                    printf("Receive Complete\n");
                }
                else if (len < 0)
                {
                    printf("Receive Failed\n");
                    exit(3);
                }
                int fd = 0;
                if ((fd = open(strcat(fileName, buff), O_CREAT | O_TRUNC | O_RDONLY, 0666)) < 0)
                {
                    perror("Open:");
                    exit(1);
                }
                while (1)
                {
                    bzero(buff, sizeof(buff));
                    len = SSL_read(ssl, buff, MAXBUF);
                    if (len == 0)
                    {
                        printf("Receive Complete\n");
                    }
                    else if (len < 0)
                    {
                        printf("Receive Failed\n");
                        exit(3);
                    }
                    if (write(fd, buff, len) < 0)
                    {
                        perror("write:");
                        exit(1);
                    }
                    else
                    {
                        printf("Write into file!");
                        break;
                    }
                }
            }
            n = 0;
            while ((buff[n++] = getchar()) != '\n')
                ;

            SSL_write(ssl, buff, strlen(buff));
            if (strncmp("exit", buff, 4) == 0)
            {
                printf("Server Exit...\n");
                break;
            }
        }
    }
}

int setSocket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

void init()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanSSL()
{
    EVP_cleanup();
}

SSL_CTX *createSSL()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void setSSL(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
    if (SSL_CTX_load_verify_locations(ctx, CA, 0) != 1)
    {
        SSL_CTX_free(ctx);
        printf("Failed to load CA file %s", CA);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    else
    {
        printf("It work!\n");
    }
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    init();
    ctx = createSSL();

    setSSL(ctx);

    sock = setSocket(PORT);

    while (1)
    {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;
        const char test[] = "Start chat...\n";

        int client = accept(sock, (struct sockaddr *)&addr, &len);
        if (client < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("Connected by Client...\n");
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("SSL connected...\n");
            SSL_write(ssl, test, strlen(test));
            Chat(ssl);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(socket);
    SSL_CTX_free(ctx);
    cleanSSL();
    return 0;
}