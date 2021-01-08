#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>


void base64_encode_update()
{
    EVP_ENCODE_CTX* encode_ctx;
    EVP_ENCODE_CTX* decode_ctx;
    printf("==========================================================\n");
    unsigned char* in = "Hello World\n";
    int inLen = strlen(in);
    unsigned char out[1024] = {0};
    int outLen = 1024;
    int outLenTotal = 0;
    unsigned char decode[1024] = {0};
    int decodeTotal = 0;
    int ret;
    //==========================================================================
    encode_ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(encode_ctx);

    for(int i = 0; i < 5; i++)
    {
        EVP_EncodeUpdate(encode_ctx, out + outLenTotal, &outLen, in, inLen);
        outLenTotal += outLen;
    }

    EVP_EncodeUpdate(encode_ctx, out + outLenTotal, &outLen, "H\n", 2);
    outLenTotal += outLen;

    EVP_EncodeFinal(encode_ctx, out + outLenTotal, &outLen);
    outLenTotal += outLen;

    printf("encode length : %d\n", outLenTotal);
    printf("encode context: %s", out);
    EVP_ENCODE_CTX_free(encode_ctx);
    //============================================================================
    printf("-------------------------------------------------------\n");
    decode_ctx = EVP_ENCODE_CTX_new();

    EVP_DecodeInit(decode_ctx);

    ret = EVP_DecodeUpdate(decode_ctx, decode, &outLen, out, outLenTotal);
    if (ret < 0)
    {
        printf("EVP_DecodeUpdate err!\n");
        return;
    }
    else
    {
        decodeTotal += outLen;
    }

    EVP_DecodeFinal(decode_ctx, decode+decodeTotal, &outLen);
    decodeTotal += outLen;

    printf("decode length:  %d\n", decodeTotal);
    printf("decode context: %s", decode);

    EVP_ENCODE_CTX_free(decode_ctx);

}


void base64_encode_block()
{
    printf("==========================================================\n");
    unsigned char* in = "Hello World\nHello World\nHello World\nHello World\nHello World\nH\n";
    int inLen = strlen(in);
    unsigned char out[1024] = {0};
    int outLenTotal = 0;
    unsigned char decode[1024] = {0};
    int decodeLen;
    int pad = 0;
    unsigned char* p;
    //===============================================================
    outLenTotal = EVP_EncodeBlock(out, in, inLen);


    printf("encode length : %d\n", outLenTotal);
    printf("encode context: %s", out);
    printf("\n-------------------------------------------------------\n");

    p = out+outLenTotal;
    for(int i = 0; i < 4; i++)
    {
        if(*p == '=')
        {
            pad++;
        }
        p--;
    }
    printf("pad:%d\n", pad);
    decodeLen = EVP_DecodeBlock(decode, out, outLenTotal);
    decodeLen -= pad;

    printf("decode length:  %d\n", decodeLen);
    printf("decode context: %s", decode);
}

int main(int argc, char const *argv[])
{
    base64_encode_update();
    base64_encode_block();
    return 0;
}
