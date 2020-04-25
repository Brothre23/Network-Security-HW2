/*File:client.c
 *Auth:sjin
 *Date：2014-03-11
 *
 */

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
    int sock_fd, send_len, read_len, fd;
    char file_name[50];
    char full_name[50] = "./test_file/";
    struct sockaddr_in dest;
    char buffer[MAXBUF];
    SSL_CTX *ctx;
    SSL *ssl;

    if (argc!= 3)
    {
        printf("IP and port number not specified!");
        exit(0);
    }

    /* SSL 庫初始化 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    if (SSL_CTX_use_certificate_file(ctx, "./CA/server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 載入使用者私鑰 */
    if (SSL_CTX_use_PrivateKey_file(ctx, "./CA/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 檢查使用者私鑰是否正確 */
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 建立一個 socket 用於 tcp 通訊 */
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket ");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化伺服器端（對方）的地址和埠資訊 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    /* 連線伺服器 */
    if (connect(sock_fd, (struct sockaddr *)&dest, sizeof(dest))!= 0)
    {
        perror("connect ");
        exit(errno);
    }
    printf("server connected\n");

    /* 基於 ctx 產生一個新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_fd);
    /* 建立 SSL 連線 */
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else
        printf("connected with %s encryption\n", SSL_get_cipher(ssl));

    printf("\navailable file list:\n");
    /* 印出檔名 */
    while (1)
    {
        SSL_read(ssl, buffer, MAXBUF);
        if (strcmp(buffer, "END_OF_FILE_LIST") == 0)
            break;
        printf("%s\n", buffer);
        bzero(buffer, MAXBUF);
    }

    /* 接收使用者輸入的檔名，並開啟檔案 */
    printf("\nplease input the name of the file you want to load:\n>");
    scanf("%s", file_name);

    strcat(full_name, file_name);

    if ((fd = open(full_name, O_RDONLY, 0666)) < 0)
    {
        perror("open ");
        exit(1);
    }

    send_len = SSL_write(ssl, file_name, strlen(file_name));
    if (send_len < 0)
        printf("'%s'message send failure! error code is %d, error messages are '%s'\n", buffer, errno, strerror(errno));

    /* 迴圈傳送檔案內容到伺服器 */
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
    printf("\nsend complete!\n");
    close(fd);

    sleep(5);
    /* 關閉連線 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock_fd);
    SSL_CTX_free(ctx);

    return 0;
}