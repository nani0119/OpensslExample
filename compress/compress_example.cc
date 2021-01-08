#include <stdlib.h>
#include <string.h>
#include <openssl/comp.h>

struct comp_method_st {
    int type;                   /* NID for compression library */
    const char *name;           /* A text string to identify the library */
    int (*init) (COMP_CTX *ctx);
    void (*finish) (COMP_CTX *ctx);
    int (*compress) (COMP_CTX *ctx,
                     unsigned char *out, unsigned int olen,
                     unsigned char *in, unsigned int ilen);
    int (*expand) (COMP_CTX *ctx,
                   unsigned char *out, unsigned int olen,
                   unsigned char *in, unsigned int ilen);
};

int custom_init(COMP_CTX *ctx)
{
    printf("---------------%s---------------\n", __func__);
}

void custom_finish(COMP_CTX *ctx)
{
    printf("---------------%s---------------\n", __func__);
}

int custom_compress(COMP_CTX *ctx,unsigned char *out, unsigned int olen, unsigned char *in, unsigned int ilen)
{
    printf("---------------%s---------------\n", __func__);
    memcpy(out, in, ilen);
    return ilen;
}

int custom_expand(COMP_CTX *ctx, unsigned char *out, unsigned int olen, unsigned char *in, unsigned int ilen)
{
    printf("---------------%s---------------\n", __func__);
    memcpy(out, in, ilen);
    return ilen;
}

static COMP_METHOD compress_custom_methon = {
    1,
    "custom",
    custom_init,
    custom_finish,
    custom_compress,
    custom_expand,
};

COMP_METHOD* COMP_custom()
{
    return &compress_custom_methon;
}

void comp_zlib()
{
    printf("=======================%s===================\n", __func__);
    COMP_CTX* ctx;
    unsigned char out[100] = {0};
    int outlen = 100;
    unsigned char* in = "hello world ";
    int inlen = strlen(in);
    unsigned char expand[100] = {0};
    int expandlen = strlen(expand);

    //ctx = COMP_CTX_new(COMP_zlib());

    ctx = COMP_CTX_new(COMP_custom());
    int len = COMP_compress_block(ctx, out, outlen, in, inlen);
    printf("compress %d :", len);
    for(int i = 0; i < len; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\n");

    len = COMP_expand_block(ctx, expand, expandlen, out, outlen);
    printf("expand:%s\n", expand);

    COMP_CTX_free(ctx);
}


int main(int argc, char const *argv[])
{
    comp_zlib();
    return 0;
}
