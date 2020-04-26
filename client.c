#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 2048

int main(int argc, char **argv)
{
    int sock_fd, len, fd;
    char file_name[50];
    char full_name[50] = "./new_file/";
    struct sockaddr_in dest;
    char buffer[MAXBUF];
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc!= 3)
    {
        printf("IP and port number not specified!");
        exit(0);
    }

    mkdir("./new_file", S_IRWXU);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, "./CA/server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./CA/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket ");
        exit(errno);
    }
    printf("socket created\n");

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    if (connect(sock_fd, (struct sockaddr *)&dest, sizeof(dest))!= 0)
    {
        perror("connect ");
        exit(errno);
    }
    printf("server connected\n");

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);

    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
        printf("connected with %s encryption\n", SSL_get_cipher(ssl));

    printf("\navailable file list:\n");

    while (1)
    {
        SSL_read(ssl, buffer, MAXBUF);
        if (strcmp(buffer, "END_OF_FILE_LIST") == 0)
            break;
        printf("%s\n", buffer);
        bzero(buffer, MAXBUF);
    }

    printf("\nplease input the name of the file you want to load:\n>");
    scanf("%s", file_name);

    if (SSL_write(ssl, file_name, strlen(file_name)) < 0)
        printf("'%s'message send failure! error code is %d, error messages are '%s'\n", buffer, errno, strerror(errno));
    strcat(full_name, file_name);

    if ((fd = open(full_name, O_CREAT | O_RDWR, 0666)) < 0)
    {
        perror("open ");
        exit(1);
    }

    bzero(buffer, MAXBUF);

    while (1)
    {
        len = SSL_read(ssl, buffer, MAXBUF);

        if ((int)len < 0)
        {
            printf("failed to receive message! error code is %d, error messages are '%s'\n", errno, strerror(errno));
            exit(1);
        }
        if (write(fd, buffer, len) < 0)
        {
            perror("write ");
            exit(1);
        }

        if (len < MAXBUF)
        {
            printf("receive complete!\n\n");
            break;
        }
    }

    close(fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);

    return 0;
}