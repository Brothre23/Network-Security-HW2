/*File:server.c
 *Auth:sjin
 *Date：2014-03-11
 *
 */
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
    int sockfd, new_fd, fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    char buffer[MAXBUF];
    char new_file_name[50] = "./new_file/";
    SSL_CTX *ctx;
    mode_t mode;
    char pwd[100];
    char *temp;
    DIR *dir;
    struct dirent *ent;

    /* 在根目錄下建立一個newfile資料夾 */
    mkdir("./new_file", S_IRWXU);

    if (argc != 2)
    {
        printf("IP and port number not found!");
        exit(0);
    }

    /* SSL 庫初始化 */
    SSL_library_init();
    /* 載入所有 SSL 演算法 */
    OpenSSL_add_all_algorithms();
    /* 載入所有 SSL 錯誤訊息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 標準相容方式產生一個 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 單獨表示 V2 或 V3標準 */
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 載入使用者的數字證書， 此證書用來發送給客戶端。 證書裡包含有公鑰 */
    getcwd(pwd, 100);
    if (strlen(pwd) == 1)
        pwd[0] = '\0';
    if (SSL_CTX_use_certificate_file(ctx, temp = strcat(pwd, "/server.crt"), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 載入使用者私鑰 */
    getcwd(pwd, 100);
    if (strlen(pwd) == 1)
        pwd[0] = '\0';
    if (SSL_CTX_use_PrivateKey_file(ctx, temp = strcat(pwd, "/server.key"), SSL_FILETYPE_PEM) <= 0)
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

    /* 開啟一個 socket 監聽 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket ");
        exit(1);
    }
    else
        printf("socket created\n");

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, NULL, sizeof(int));

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(atoi(argv[1]));
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind ");
        exit(1);
    }
    else
        printf("binded\n");

    if (listen(sockfd, 1) == -1)
    {
        perror("listen");
        exit(1);
    }
    else
        printf("begin listen\n");

    while (1)
    {
        // printf("new connection\n");
        SSL *ssl;
        len = sizeof(struct sockaddr);
        /* 等待客戶端連上來 */
        if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &len)) == -1)
        {
            perror("accept ");
            exit(errno);
        }
        else
            printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port), new_fd);

        /* 基於 ctx 產生一個新的 SSL */
        ssl = SSL_new(ctx);
        /* 將連線使用者的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);
        /* 建立 SSL 連線 */
        if (SSL_accept(ssl) == -1)
        {
            perror("accept ");
            close(new_fd);
            break;
        }

        if ((dir = opendir("./test_file/")) != NULL)
        {
            /* print all the files and directories within directory */
            while ((ent = readdir(dir)) != NULL)
                SSL_write(ssl, ent->d_name, strlen(ent->d_name));
            closedir(dir);
            SSL_write(ssl, "END_OF_FILE_LIST", 17);
        }
        else
            perror("open directory ");

        /* 接受客戶端所傳檔案的檔名並在特定目錄建立空檔案 */
        bzero(buffer, MAXBUF);
        bzero(new_file_name + 11, 39);
        len = SSL_read(ssl, buffer, MAXBUF);

        if (len == 0)
            printf("receive complete! \n");
        else if (len < 0)
            printf("failed to receive message! error code is %d, error messages are '%s'\n", errno, strerror(errno));
        strcat(new_file_name, buffer);

        if ((fd = open(new_file_name, O_CREAT | O_RDWR, 0666)) < 0)
        {
            perror("open ");
            exit(1);
        }

        bzero(buffer, MAXBUF);
        /* 接收客戶端的資料並寫入檔案 */
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
                printf("receive complete!\n");
                break;
            }
        }
        /* 關閉檔案 */
        close(fd);
        /* 關閉 SSL 連線 */
        SSL_shutdown(ssl);
        /* 釋放 SSL */
        SSL_free(ssl);
        /* 關閉 socket */
        close(new_fd);
    }

    /* 關閉監聽的 socket */
    close(sockfd);
    /* 釋放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}