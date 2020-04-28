#include "Share.h"

#define CA "./CA.pem"
#define CLIENT_KEY "./client-key.pem"
#define CLIENT_CERT "./Client-cert.pem"

void Chat(SSL *ssl)
{
    char buff[MAXBUF];
    int n;
    for (;;)
    {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        SSL_write(ssl, buff, strlen(buff));
        bzero(buff, sizeof(buff));
        SSL_read(ssl, buff, sizeof(buff));
        printf("From Server : %s", buff);
        if ((strncmp(buff, "exit", 4)) == 0)
        {
            printf("Client Exit...\n");
            break;
        }
        else if (strncmp("file", buff, 4) == 0)
        {
            char fileName[50], sendFN[20];
            int fd = 0;
            printf("\nPlease input fileName:\n>");
            scanf("%s", fileName);
            if ((fd = open(fileName, O_RDONLY, 0666)) < 0)
            {
                perror("open:");
                exit(1);
            }
            int j = 0;
            for (int i = 0; i < strlen(fileName); i++)
            {
                if (fileName[i] == '/')
                {
                    j = 0;
                    continue;
                }
                else
                {
                    sendFN[j] = fileName[i];
                    ++j;
                }
            }
            int len = SSL_write(ssl, sendFN, strlen(sendFN));
            bzero(buff, sizeof(buff));
            int size = 0;
            while ((size = read(fd, buff, 1024)))
            {
                if (size < 0)
                {
                    perror("read");
                    exit(1);
                }
                else
                {
                    len = SSL_write(ssl, buff, size);
                }
            }
            printf("Send Complete!\n");
        }
    }
}

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("Cert Info:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Cert: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("From: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("Cert Failed！\n");
    }
}

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;
    const SSL_METHOD *method;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    if (!ctx)
    {
        printf("create ctx is failed.\n");
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

    if (SSL_CTX_load_verify_locations(ctx, CA, 0) != 1)
    {
        SSL_CTX_free(ctx);
        printf("Failed to load CA file %s", CA);
    }
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
    {
        SSL_CTX_free(ctx);
        printf("Call to SSL_CTX_set_default_verify_paths failed");
    }
    if (SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx);
        printf("Failed to load client certificate from %s", CLIENT_KEY);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_KEY, SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx);
        printf("Failed to load client private key from %s", CLIENT_KEY);
    }

    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        SSL_CTX_free(ctx);
        printf("SSL_CTX_check_private_key failed");
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(PORT);
    dest.sin_addr.s_addr = htonl(INADDR_ANY);

    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("SSL_new error.\n");
    }
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1)
    {
        printf("SSL_connect fail.\n");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    bzero(buffer, MAXBUF + 1);
    len = SSL_read(ssl, buffer, MAXBUF);
    if (len > 0)
    {
        printf("%s\n", buffer);
    }
    else
    {
        printf("Failed\n");
    }
    bzero(buffer, MAXBUF + 1);
    Chat(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}