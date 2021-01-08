#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define BUF_LEN 1024
#define MAX_STRING_LEN 2048

//xnet_select x defines
#define READ_STATUS 0
#define WRITE_STATUS 1
#define EXCPT_STATUS 2

/* flag to set request with ssl or not. */
static int bIsHttps = 1;
static int timeout_sec = 10;
static int timeout_microsec = 0;

void err_doit(int errnoflag, const char *fmt, va_list ap)
{
    int errno_save;
    char buf[MAX_STRING_LEN];

    errno_save = errno;
    vsprintf(buf, fmt, ap);
    if (errnoflag)
        sprintf(buf + strlen(buf), ": %s", strerror(errno_save));
    strcat(buf, "\n");
    fflush(stdout);
    fputs(buf, stderr);
    fflush(NULL);
    return;
}

/* Print a message and terminate. */
void err_quit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    err_doit(0, fmt, ap);
    va_end(ap);
    exit(1);
}

/*
s    - SOCKET
sec  - timeout seconds
usec - timeout microseconds
x    - select status
*/
int xnet_select(int s, int sec, int usec, short x)
{
    int st = errno;
    struct timeval to;
    fd_set fs;
    to.tv_sec = sec;
    to.tv_usec = usec;
    FD_ZERO(&fs);
    FD_SET(s, &fs);
    switch (x)
    {
    case READ_STATUS:
        st = select(s + 1, &fs, 0, 0, &to);
        break;
    case WRITE_STATUS:
        st = select(s + 1, 0, &fs, 0, &to);
        break;
    case EXCPT_STATUS:
        st = select(s + 1, 0, 0, &fs, &to);
        break;
    }
    return (st);
}

/* create common tcp socket connection */

int create_tcpsocket(const char *host, const unsigned short port)
{
    int ret;

    char *transport = "tcp";
    struct hostent *phe;    /* pointer to host information entry */
    struct protoent *ppe;   /* pointer to protocol information entry */
    struct sockaddr_in sin; /* an Internet endpoint address */
    int s;                  /* socket descriptor and socket type */

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    if ((sin.sin_port = htons(port)) == 0)
        err_quit("invalid port '%d'\n", port);

    /* Map host name to IP address, allowing for dotted decimal */
    if (phe = gethostbyname(host))
        memcpy(&sin.sin_addr, phe->h_addr, phe->h_length);
    else if ((sin.sin_addr.s_addr = inet_addr(host)) == INADDR_NONE)
        err_quit("can't get '%s' host entry\n", host);

    /* Map transport protocol name to protocol number */
    if ((ppe = getprotobyname(transport)) == 0)
        err_quit("can't get '%s' protocol entr\n", transport);

    /* Allocate a common TCP socket */
    s = socket(PF_INET, SOCK_STREAM, ppe->p_proto);
    if (s < 0)
        err_quit("can't create socket: %s\n", strerror(errno));

    if (bIsHttps != 1)
    {
        /* Connect the socket with timeout */
        fcntl(s, F_SETFL, O_NONBLOCK);
        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
        {
            if (errno == EINPROGRESS)
            { // it is in the connect process
                struct timeval tv;
                fd_set writefds;
                tv.tv_sec = timeout_sec;
                tv.tv_usec = timeout_microsec;
                FD_ZERO(&writefds);
                FD_SET(s, &writefds);
                if (select(s + 1, NULL, &writefds, NULL, &tv) > 0)
                {
                    int len = sizeof(int);
                    //下面的一句一定要，主要针对防火墙
                    getsockopt(s, SOL_SOCKET, SO_ERROR, &errno, &len);
                    if (errno != 0)
                        ret = 1;
                    else
                        ret = 0;
                }
                else
                    ret = 2; //timeout or error happen
            }
            else
                ret = 1;
        }
        else
        {
            ret = 1;
        }
    }
    else
    {
        /* create common tcp socket.seems non-block type is not supported by ssl. */
        ret = connect(s, (struct sockaddr *)&sin, sizeof(sin));
    }

    if (ret != 0)
    {
        close(s);
        err_quit("can't connect to %s:%d", host, port);
    }

    return s;
}

//ssl_http_example www.aaa.com 80 / 0
//ssl_http_example www.aaa.com 443 / 1

int ssl_http(int argc, char const *argv[])
{
    printf("=========================================%s==================================\n", __func__);
    struct hostent *hptr;
    const char* host = "127.0.0.1";
    unsigned short port = 80;
    char str[INET_ADDRSTRLEN];
    int fd;

    SSL *ssl;
    SSL_CTX *ctx;

    int n, ret;
    char buf[BUF_LEN];
    char *requestpath = "/";

    if (argc == 5)
    {
        host = argv[1];
        port = atoi(argv[2]);
        requestpath = argv[3];
        bIsHttps = atoi(argv[4]);
    }
    else
    {
        printf("usage:\n");
        printf("ssl_http_example www.aaa.com 80 / 0  for no-ssl\n");
        printf("ssl_http_example www.aaa.com 443 / 1 for ssl\n");
        err_quit("paramter error!");
    }

#if 0
    // url to ip
    if((hptr = gethostbyname(host)) == NULL)
    {
        err_quit("gethostbyname error for host: %s: %s", host, hstrerror(h_errno));
    }
    
    host = inet_ntop(hptr->h_addrtype, hptr->h_addr_list[0], str, sizeof(str));
    printf("server ip addr:%s:%d\n",host, port);
#endif

    /* make connection to the cache server */
    fd = create_tcpsocket(host, port);

    /* http request. */
    sprintf(buf, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", requestpath, host);

    if (bIsHttps != 1)
    {
        if (xnet_select(fd, timeout_sec, timeout_microsec, WRITE_STATUS) > 0)
        {
            /* send off the message */
            write(fd, buf, strlen(buf));
        }
        else
        {
            err_quit("Socket I/O Write Timeout %s:%d\n", host, port);
        }
        printf("Server response: OK/n");
        while (xnet_select(fd, timeout_sec, timeout_microsec, READ_STATUS) > 0)
        {
            if ((n = read(fd, buf, BUF_LEN - 1)) > 0)
            {
                buf[n] = 0;
                printf("%s", buf);
            }
            else
            {
                break;
            }
        }
        // close the plain socket handler.
        close(fd);
    }
    else  /*https*/
    {
        SSL_load_error_strings();
        SSL_library_init();
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == NULL)
        {
            err_quit("init SSL CTX failed:%s\n", ERR_reason_error_string(ERR_get_error()));
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            err_quit("new SSL with created CTX failed:%s\n", ERR_reason_error_string(ERR_get_error()));
        }

        ret = SSL_set_fd(ssl, fd);
        if (ret == 0)
        {
            err_quit("add SSL to tcp socket failed:%s\n", ERR_reason_error_string(ERR_get_error()));
        }

        /* PRNG */
        RAND_poll();
        while (RAND_status() == 0)
        {
            unsigned short rand_ret = rand() % 65536;
            RAND_seed(&rand_ret, sizeof(rand_ret));
        }

        /* SSL Connect */
        ret = SSL_connect(ssl);
        if (ret != 1)
        {
            err_quit("SSL connection failed:%s\n",ERR_reason_error_string(ERR_get_error()));
        }

        printf("connect to server success\n");
        // https socket write.
        SSL_write(ssl, buf, strlen(buf));
        printf("write request to server\n");
        while ((n = SSL_read(ssl, buf, BUF_LEN-1)) > 0)
        {
            buf[n] = 0;
            write(1, buf, n);
        }
        if (n != 0)
        {
            err_quit("SSL read failed:%s\n", ERR_reason_error_string(ERR_get_error()));
        }
        // close ssl tunnel.
        ret = SSL_shutdown(ssl);
        if (ret != 1)
        {
            close(fd);
            err_quit("SSL shutdown failed:%s\n", ERR_reason_error_string(ERR_get_error()));
        }

        // close the plain socket handler.
        close(fd);

        // clear ssl resource.
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        ERR_free_strings();
    }
}

int main(int argc, char const *argv[])
{
    return ssl_http(argc, argv);
}
