#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define CERTF "server.crt" /*服务端的证书(需经CA签名)*/
#define KEYF "server.key"  /*服务端的私钥(建议加密存储)*/
#define CACERT "ca.crt"    /*CA 的证书*/
#define PORT 9999          /*准备绑定的端口*/

#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(1)
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(1);        \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(2);                     \
    }

void ssl_server()
{
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    int client_len;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *client_cert;
    char *str;
    char buf[4096];
    const SSL_METHOD *meth;

    printf("========================================%s==============================\n",__func__);
    /*为打印调试信息作准备*/
    SSL_load_error_strings();

    /*初始化*/
    OpenSSL_add_ssl_algorithms();

    /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    meth = TLSv1_2_server_method();

    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    /*验证与否*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /*若验证,则放置CA证书*/
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }

    // 填充server使用私钥的密码
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "111111");

    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public key/n");
        exit(5);
    }

    // 设置加密套件
    //SSL_CTX_set_cipher_list(ctx, "RC4-MD5");
    SSL_CTX_set_cipher_list(ctx, "ALL");

    /*开始正常的TCP socket过程.................................*/
    printf("Begin TCP socket.../n");

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");

    memset(&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(PORT);

    err = bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
    CHK_ERR(err, "bind");

    /*接受TCP链接*/
    err = listen(listen_sd, 5);
    CHK_ERR(err, "listen");

    client_len = sizeof(sa_cli);
    sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);
    CHK_ERR(sd, "accept");

    // 只接受一个client
    shutdown(listen_sd, 2);

    printf("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);

    /*TCP连接已建立,进行服务端的SSL过程. */
    printf("Begin server side SSL\n");

    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    SSL_set_fd(ssl, sd);
    err = SSL_accept(ssl);
    printf("SSL_accept finished\n");
    CHK_SSL(err);

    /*打印所有加密算法的信息(可选)*/
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*得到服务端的证书并打印些信息(可选) */
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL)
    {
        printf("Client certificate:\n");

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\tsubject: %s\n", str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\tissuer: %s\n", str);

        X509_free(client_cert); /*如不再需要,需将证书释放 */
    }
    else
    {
        printf("Client does not have certificate.\n");
    }

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    err = SSL_read(ssl, buf, sizeof(buf) -1);
    CHK_SSL(err);
    buf[err] = 0;
    printf("%s\n",buf);

    while (1)
    {
        memset(buf, 0, sizeof(buf));
        err = SSL_read(ssl, buf, sizeof(buf) -1);
        if(err <= 0)
        {
            printf("shutdown ssl\n");
            break;
        }

        CHK_SSL(err);
        buf[err] = 0;
        printf("I hear you:%s\n",buf);

        err = SSL_write(ssl, buf, err);
        CHK_SSL(err);
    }

    /* 收尾工作*/
    shutdown(sd, 2);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main(int argc, char const *argv[])
{
    ssl_server();
    return 0;
}
