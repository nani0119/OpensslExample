#include <stdio.h>
#include <string.h>

#include <openssl/ocsp.h>

//OCSP， Online Certificate Status Protocol， rfc2560
//用于实时表明证书状态。 OCSP 客户端通过查询 OCSP 服务来确定一个证书的状态。 OCSP 可以通过 HTTP
//协议来实现。 rfc2560 定义了 OCSP 客户端和服务端的消息格式

//ocsp 的编程主要是生成 ocsp 请求、解析 ocsp 请求、生成 ocsp 响应、解析 ocsp 响
//应得到结果以及消息的签名和验证。客户端可用 ocsp_cl.c 中提供的函数，服务端可用
//ocsp_srv.c 中提供的函数.典型的应用程序请参考 apps/ocsp.c。

int main(int argc, char*argv[])
{
    printf("=====================================ocsp==============================\n");
    return 0;
}