#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/objects.h>
#include <openssl/bn.h>

// https://blog.csdn.net/aaqian1/article/details/89299520
/*
Digital Signature Algorithm (DSA)算法是一种公钥算法。其密钥由如下部分组成：
1） p
一个大素数，长度为 L(64 的整数倍)比特。
2） q
一个 160 比特素数。
3） g
g=h(p-1)/q mod p，其中 h 小于 p-1。
4） x
小于 q。
5) y
y=g
x mod p。
其中 x 为私钥， y 为公钥。 p、 q 和 g 是公开信息(openssl 中称为密钥参数)。
DSA 签名包括两部分，如下：
r = (gk mod p) mod q
s = (k-1 (H(m) + xr)) mod q
其中， H(m)为摘要算法；
DSA 验签如下：
w = s
-1
mod q
u1 = (H(m) * w) mod q
*/

void dsa_sign_verify()
{
    int ret;
    DSA *d;
    const char* data = "hello world";
    int bits = 1024;
    unsigned char signret[200] = {0};
    int signlen = 200;
    BIGNUM* pubKey;
    BIGNUM* privKey;
    printf("======================%s======================\n",__func__);

    d = DSA_new();
    ret = DSA_generate_parameters_ex(d, bits, NULL, 0, NULL, NULL, NULL);
    if(ret != 1)
    {
        DSA_free(d);
        printf("DSA_generate_parameters_ex fail\n");
    }

    ret = DSA_generate_key(d);
    if(ret != 1)
    {
        DSA_free(d);
        printf("DSA_generate_key fail\n");
    }
    else
    {
        printf("DSA_size:%d\n", DSA_size(d));
        printf("DSA_bits:%d\n", DSA_bits(d));
        DSA_print_fp(stdout, d, 0);
        printf("-------------------------------------------------\n");
    }
#if 1
    //====================================================
    BIGNUM* p, *q, *g;
    DSA* dsaPriv;
    DSA* dsaPub;
    DSA_get0_pqg(d, &p, &q, &g);

    pubKey = (BIGNUM*)DSA_get0_pub_key(d);
    dsaPub = DSA_new();
    DSA_set0_pqg(dsaPub, p, q, g);
    DSA_set0_key(dsaPub, pubKey, NULL);
    DSA_print_fp(stdout, dsaPub, 0);
#endif

    ret=DSA_sign(NID_md5, data, strlen(data),signret, &signlen, d);
    if (ret != 1)
    {
        printf("DSA_sign err!\n");
        DSA_free(d);
        return;
    }

    ret = DSA_verify(NID_md5, data, strlen(data), signret, signlen, dsaPub);
    if (ret != 1)
    {
        printf("DSA_verify err!\n");
        DSA_free(d);
    }
    else
    {
        printf("DSA_verify success\n");
    }

    DSA_free(d);
}

int main(int argc, char const *argv[])
{
    dsa_sign_verify();
    return 0;
}
