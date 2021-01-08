#include <stdio.h>
#include <string.h>

#include <openssl/ocsp.h>

/*
证书撤销列表(Certificate Revocation List，简称 CRL)，是一种包含撤销的证书列表的签
名数据结构。 CRL 是证书撤销状态的公布形式， CRL 就像信用卡的黑名单，用于公布某些
数字证书不再有效。
CRL 是一种离线的证书状态信息。它以一定的周期进行更新。 CRL 可以分为完全 CRL
和增量 CRL。在完全 CRL 中包含了所有的被撤销证书信息，增量 CRL 由一系列的 CRL 来
表明被撤销的证书信息，它每次发布的 CRL 是对前面发布 CRL 的增量扩充。
基本的 CRL 信息有：被撤销证书序列号、撤销时间、撤销原因、签名者以及 CRL 签名
等信息。
基于 CRL 的验证是一种不严格的证书认证。 CRL 能证明在 CRL 中被撤销的证书是无
效的。但是，它不能给出不在 CRL 中的证书的状态。如果执行严格的认证，需要采用在线
方式进行认证，即 OCSP 认证。
*/

int main(int argc, char*argv[])
{
    printf("=====================================crl==============================\n");
    return 0;
}