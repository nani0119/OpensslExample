#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ossl_typ.h>
#include <openssl/objects.h>
#include <openssl/md5.h>

void rsa_key_item()
{
    RSA* rsaParis;
    BIGNUM* bne;
    char* data;
    int bits = 512;
    printf("======================%s=====================\n", __func__);
    rsaParis = RSA_new();
    bne = BN_new();
    BN_set_word(bne, RSA_3);
    RSA_generate_key_ex(rsaParis, bits, bne, NULL);
    RSA_print_fp(stdout, rsaParis, 0);

    //素数p
    const BIGNUM * p = RSA_get0_p(rsaParis);
    data = BN_bn2hex(p);
    printf("p = %s\n", data);

    //素数q
    const BIGNUM * q = RSA_get0_q(rsaParis);
    data = BN_bn2hex(q);
    printf("q = %s\n", data);

    // n = p*q
    const BIGNUM * n = RSA_get0_n(rsaParis);
    data = BN_bn2hex(n);
    printf("n = %s\n", data);

    // e 公钥指数 (e, n)公钥
    const BIGNUM * e = RSA_get0_e(rsaParis);
    data = BN_bn2hex(e);
    printf("e = %s\n", data);

    // d 私钥指数　（d, n）私钥
    const BIGNUM * d = RSA_get0_d(rsaParis);
    data = BN_bn2hex(d);
    printf("d = %s\n", data);

    // e*dmp1 = 1 (mod (p-1))
    const BIGNUM * dmp1 = RSA_get0_dmp1(rsaParis);
    data = BN_bn2hex(dmp1);
    printf("dmp1 = %s\n", data);

    // e*dmq1 = 1 (mod (q-1))
    const BIGNUM * dmq1 = RSA_get0_dmq1(rsaParis);
    data = BN_bn2hex(dmq1);
    printf("dmq1 = %s\n", data);

    // q*iqmp = 1 (mod p )
    const BIGNUM * iqmp = RSA_get0_iqmp(rsaParis);
    data = BN_bn2hex(iqmp);
    printf("iqmp = %s\n", data);

    BN_free(bne);
    RSA_free(rsaParis);
}

// 大文件----> AES加密 ---->RSA传递AES秘钥----> AES解密
void rsa_gen_key_enc_dec()
{
    printf("======================%s=====================\n", __func__);
    int ret = 0;
    RSA* rsaParis;
    RSA* rsaPublic;
    RSA* rsaPrivate;
    BIGNUM* e;
    int bits = 512;
    char* plain="01234567890";
    int plainlen = strlen(plain);
    unsigned char cipper[128]={0};
    int cipperlen = 128;
    unsigned char newplain[128]={0};
    int newplainlen = 128;
    
    //============================================
    // gen key
    rsaParis = RSA_new();
    e = BN_new();
    BN_set_word(e, RSA_3);
    ret = RSA_generate_key_ex(rsaParis, bits, e, NULL);
    if (ret != 1)
    {
        printf("RSA_generate_key_ex err!\n");
    }
    else
    {
        printf("rsa version:%d\n",RSA_get_version(rsaParis));
    }
    
    RSA_print_fp(stdout, rsaParis, 0);

    printf("----------------------------------------\n");
    // 明文
    printf("plain:\t");
    for(int i =0; i<plainlen; i++)
    {
        printf("%02x ",plain[i]);
    }
    printf("\n");

    printf("RSA_bits: %d\n",RSA_bits(rsaParis));
    printf("RSA_security_bits: %d\n",RSA_security_bits(rsaParis));
    printf("RSA_size: %d\n",RSA_size(rsaParis));

    printf("----------------------------------------\n");
    // 公钥加密
    // plainlen must be less than RSA_size(rsa) - 11 for the PKCS #1 v1.5
    // plainlen must be less than RSA_size(rsa) - 41 for RSA_PKCS1_OAEP_PADDING
    // plainlen must be less than RSA_size(rsa) for RSA_NO_PADDING
    rsaPublic = RSAPublicKey_dup(rsaParis);
    RSA_print_fp(stdout, rsaPublic, 10);
    printf("----------------------------------------\n");
    cipperlen = RSA_public_encrypt(plainlen, plain, cipper, rsaPublic, RSA_PKCS1_OAEP_PADDING);
    printf("cipper:\t");
    for(int i =0;i<cipperlen;i++){
        printf("%02x ",cipper[i]);
    }
    printf("\n");

    printf("----------------------------------------\n");
    // 私钥解密
    rsaPrivate = RSAPrivateKey_dup(rsaParis);
    RSA_print_fp(stdout, rsaPrivate, 10);
    printf("----------------------------------------\n");
    newplainlen = RSA_private_decrypt(cipperlen, cipper, newplain, rsaPrivate, RSA_PKCS1_OAEP_PADDING);
    printf("new plain:\t");
    for(int i =0; i<newplainlen; i++)
    {
        printf("%02x ",newplain[i]);
    }
    printf("\n");



    RSA_free(rsaParis);
    RSA_free(rsaPublic);
    RSA_free(rsaPrivate);
    BN_free(e);
}


// 大文件----> MD5 ----> sig------>verify
void rsa_sign_verify()
{
    printf("======================%s=====================\n", __func__);
    int ret = 0;
    RSA* rsaParis;
    RSA* rsaPublic;
    RSA* rsaPrivate;
    unsigned char sigret[4096] = {0};
    int sigretlen = 4096;
    BIGNUM* e;
    int bits = 512;
    unsigned char md[16] = {0};  //128
    char* data="hello word";
    int datalen = strlen(data);
    rsaParis = RSA_new();
    e = BN_new();
    BN_set_word(e, RSA_3);
    RSA_generate_key_ex(rsaParis, bits, e, NULL);
    rsaPublic = RSAPublicKey_dup(rsaParis);
    rsaPrivate = RSAPrivateKey_dup(rsaParis);
    printf("rsa size:%d\n", RSA_size(rsaParis));

    // ==================================
    // 计算摘要
    MD5(data, strlen(data), md);

    //======================================
    // 私钥签名
    ret = RSA_sign(NID_md5, md, 16, sigret, &sigretlen, rsaPrivate);
    printf("sigretlen:%d\n",sigretlen);
    if(ret == 1)
    {
        printf("sigret: ");
        for (int i = 0; i < sigretlen; i++)
        {
            printf("%02x", sigret[i]);
        }
        printf("\n");
    }
    else
    {
        printf("RSA_sign fail\n");
    }


    //================================================
    // 公钥验签
    //data = "1111111";
    // 计算摘要
    memset(md, 0 , 16);
    MD5(data, strlen(data), md);
    ret = RSA_verify(NID_md5, md, 16, sigret, sigretlen, rsaPublic);
    if(ret == 1)
    {
        printf("RSA_verify success\n");
    }
    else
    {
        printf("RSA_verify fail\n");
    }
    
    
    RSA_free(rsaParis);
    RSA_free(rsaPublic);
    RSA_free(rsaPrivate);
}

int main(int argc, char const *argv[])
{
    rsa_key_item();
    rsa_gen_key_enc_dec();
    rsa_sign_verify();
    return 0;
}
