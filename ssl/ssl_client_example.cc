#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define CERTF "client.crt"      /*客户端的证书(需经CA签名)*/
#define KEYF "client.key"       /*客户端的私钥(建议加密存储)*/
#define CACERT "ca.crt"         /*CA 的证书*/
#define PORT 9999               /*服务端的端口*/
#define SERVER_ADDR "127.0.0.1" /*服务段的IP地址*/

#define CHK_NULL(x)  \
    if ((x) == NULL) \
    exit(-1)
#define CHK_ERR(err, s) \
    if ((err) == -1)    \
    {                   \
        perror(s);      \
        exit(-2);       \
    }
#define CHK_SSL(err)                 \
    if ((err) == -1)                 \
    {                                \
        ERR_print_errors_fp(stderr); \
        exit(-3);                    \
    }

int key_passwd_cb(char *passwd, int size, int rwflag, void *userdata)
{
    printf("====================%s:%s==================\n",__func__, (char*)userdata);
    if(userdata)
    {
        strcpy(passwd, (char*)userdata);
    }
    else
    {
        if(rwflag == 1)
        {
            printf("please input passwd for encrypt:");
        }
        else
        {
            printf("please input passwd for decrypt:");
        }
        scanf("%s", passwd);
    }
    return strlen(passwd);
}

void ssl_client()
{
    int err;
    int sd;
    struct sockaddr_in sa;
    SSL_CTX *ctx;
    SSL *ssl;
    X509 *server_cert;
    char *str;
    const SSL_METHOD *meth;
    int seed_int[100]; /*存放随机序列*/
    char buf[4096];

    printf("================================%s================================\n", __func__);

    /*初始化*/
    OpenSSL_add_ssl_algorithms();

    /*为打印调试信息作准备*/
    SSL_load_error_strings();

    /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    meth = TLSv1_2_client_method();

    /*申请SSL会话环境*/
    ctx = SSL_CTX_new(meth);
    CHK_NULL(ctx);

    /*验证与否,是否要验证对方*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    /*若验证对方,则放置CA证书*/
    SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

    /*加载自己的证书*/
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }

    // 填充client使用私钥的密码
    SSL_CTX_set_default_passwd_cb(ctx, key_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "111111");

    /*加载自己的私钥,以用于签名*/
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-3);
    }

    /*调用了以上两个函数后,检验一下自己的证书与私钥是否配对*/
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public key\n");
        exit(-4);
    }

    /*构建随机数生成机制*/
    srand((unsigned)time(NULL));
    for (int i = 0; i < 100; i++)
    {
        seed_int[i] = rand();
    }
    RAND_seed(seed_int, sizeof(seed_int));

    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "socket");

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVER_ADDR); /* Server IP */
    sa.sin_port = htons(PORT);                   /* Server Port number */

    err = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
    CHK_ERR(err, "connect");

    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    printf("Begin SSL negotiation\n");

    /*申请一个SSL套接字*/
    ssl = SSL_new(ctx);
    CHK_NULL(ssl);

    /*绑定读写套接字*/
    SSL_set_fd(ssl, sd);
    err = SSL_connect(ssl);
    CHK_SSL(err);

    /*打印所有加密算法的信息*/
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));

    /*得到服务端的证书并打印些信息*/
    server_cert = SSL_get_peer_certificate(ssl);
    CHK_NULL(server_cert);
    printf("Server certificate: ok\n");

    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("/t subject: %s\n", str);

    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    CHK_NULL(str);
    printf("/t issuer: %s\n", str);

    X509_free(server_cert); /*如不再需要,需将证书释放 */

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    err = SSL_write(ssl, "Hello Server!", strlen("Hello Server!"));
    CHK_SSL(err);

    while (1)
    {
        memset(buf, 0, sizeof(buf));
        err = scanf("%s", &buf);
        if (err == EOF)
        {
            printf("shutdown ssl\n");
            break;
        }
        err = SSL_write(ssl, buf, strlen(buf));
        
        err = SSL_read(ssl, buf, sizeof(buf) - 1);
        CHK_SSL(err);

        buf[err] = 0;
        printf("I got %d chars:'%s'\n", err, buf);
    }

    SSL_shutdown(ssl); /* send SSL/TLS close_notify */

    /* 收尾工作 */
    shutdown(sd, 2);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main(int argc, char const *argv[])
{
    ssl_client();
    return 0;
}
