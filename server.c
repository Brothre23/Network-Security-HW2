#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <dirent.h>

#define MAXBUF 2048

int main(int argc, char **argv)
{
    int server_fd, client_fd, fd, read_len, send_len;
    socklen_t sock_len;
    struct sockaddr_in server_addr, client_addr;
    char buffer[MAXBUF];
    char file_name[50] = "./test_file/";
    SSL_CTX *ctx;
    DIR *dir;
    struct dirent *entry;

    if (argc != 2)
    {
        printf("port number not specified!");
        exit(0);
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, "./CA/client.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./CA/client.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    if ((server_fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket ");
        exit(1);
    }
    printf("socket created\n");

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, NULL, sizeof(int));

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[1]));
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind ");
        exit(1);
    }
    printf("binded\n");

    if (listen(server_fd, 1) == -1)
    {
        perror("listen ");
        exit(1);
    }
    printf("begin listen\n\n");

    while (1)
    {
        SSL *ssl;
        sock_len = sizeof(struct sockaddr);

        if ((client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &sock_len)) == -1)
        {
            perror("accept ");
            exit(errno);
        }
        printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_fd);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) == -1)
        {
            perror("accept ");
            close(client_fd);
            break;
        }

        if ((dir = opendir("./test_file/")) != NULL)
        {
            while ((entry = readdir(dir)) != NULL)
                SSL_write(ssl, entry->d_name, strlen(entry->d_name));
            closedir(dir);
            SSL_write(ssl, "END_OF_FILE_LIST", 17);
        }
        else
            perror("open directory ");

        if (SSL_read(ssl, buffer, MAXBUF) < 0)
            printf("failed to receive message! error code is %d, error messages are '%s'\n", errno, strerror(errno));
        bzero(file_name + 12, 38);
        strcat(file_name, buffer);

        if ((fd = open(file_name, O_RDONLY, 0666)) < 0)
        {
            perror("open ");
            exit(1);
        }

        bzero(buffer, MAXBUF);
        while ((read_len = read(fd, buffer, MAXBUF)))
        {
            if (read_len < 0)
            {
                perror("read ");
                exit(1);
            }
            else
            {
                send_len = SSL_write(ssl, buffer, read_len);
                if (send_len < 0)
                    printf("'%s'message send failure! error code is %d, error messages are '%s'\n", buffer, errno, strerror(errno));
            }
            bzero(buffer, MAXBUF);
        }
        printf("send complete!\n\n");
        
        close(fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}