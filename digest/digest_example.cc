#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>


void print_bin(unsigned char* tag ,unsigned char* data, int len)
{
    printf("%s: ", tag);
    for(int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void md5()
{
    MD5_CTX md5_ctx;
    printf("=====================%s====================\n", __func__);
    unsigned char md[16] = {0};  //128
    char* data = "hello world";   // echo -n "hello world" | md5sum    note -n


    MD5_Init(&md5_ctx);

    for(int i = 0; i < 1; i++)
    {
        MD5_Update(&md5_ctx, data, strlen(data));
    }

    MD5_Final(md, &md5_ctx);
    print_bin("md5", md, 16);
    //====================================================================

    memset(md, 0 , 16);
    MD5(data, strlen(data), md);
    print_bin("md5", md, 16);

}

void sha256()
{
    printf("=====================%s====================\n", __func__);
    SHA256_CTX sha256_ctx;
    unsigned char sha[32] = {0};  //256
    char* data = "hello world";

    SHA256_Init(&sha256_ctx);
    for(int i = 0; i < 1; i++)
    {
        SHA256_Update(&sha256_ctx, data, strlen(data));
    }
    SHA256_Final(sha, &sha256_ctx);
    print_bin("sha256", sha, 32);
    //======================================================

    SHA256(data, strlen(data), sha);
    print_bin("sha256", sha, 32);
}

void hamc()
{
    printf("=====================%s====================\n", __func__);
    unsigned char key[16] = {1};
    int keylen = 16;
    unsigned char md[32] = {0};
    unsigned int mdlen = 32;
    char* data = "hello world";
    //============================================================
    HMAC_CTX * ctx = HMAC_CTX_new();

    HMAC_Init(ctx, key, keylen, EVP_md5());

    for(int i = 0; i < 1; i++)
    {
        HMAC_Update(ctx, data, strlen(data));
    }

    HMAC_Final(ctx, md, &mdlen);

    HMAC_CTX_free(ctx);
    print_bin("hmac", md, mdlen);

    //============================================================
    memset(md, 0, mdlen);
    HMAC(EVP_md5(), key, keylen, data, strlen(data), md, &mdlen);

    print_bin("hmac", md, mdlen);
}


int main(int argc, char const *argv[])
{
    md5();
    sha256();
    hamc();
    return 0;
}
