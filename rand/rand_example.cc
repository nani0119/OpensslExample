#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>



void randomDataOut(unsigned char* data, int len)
{
    BIO* base64 = BIO_new(BIO_f_base64());

    BIO* out = BIO_new(BIO_s_file());
    BIO_push(base64, out);
    BIO_set_fp(out, stdout, BIO_NOCLOSE);
    BIO_write(base64, data, len);
    BIO_flush(base64);
    BIO_free_all(base64);
}

void randomDataOut(const char* file)
{
    unsigned char data[1024];
    BIO* in = BIO_new_file(file, "r");
    BIO_read(in, data, sizeof(data));
    BIO_free(in);
    randomDataOut(data, 1024);
}

void rand_example()
{
    char buf[20] = {1};
    char filename[50] = {0};
    const char* p;
    int ret;
    unsigned char random[20] = {0};
    int pollCnt = 0;

    RAND_add(buf, 10, 1);
    RAND_seed(buf,20);

    while(1)
    {
        ret = RAND_status();
        if(ret == 1)
        {
            //printf("seeded enough!\n");
            break;
        }
        else
        {
            printf("not enough sedded!, pollCnt:%d\n", ++pollCnt);
            RAND_poll();
        }
        
    }

    ret=RAND_bytes(random, 20);
    if(ret == 1)
    {
        randomDataOut(random,20);
    }
    else
    {
        printf("RAND_bytes() fail:%ld\n\n\n", ERR_get_error());
    }
    
//==============================================================
    p=RAND_file_name(filename,50);
    if (p == NULL)
    {
        printf("can not get rand file\n");
    }

    int len =RAND_write_file(p);
    printf("\n\n\nwrite to rand file:%s %d bytes data\n\n\n", p, len);
    randomDataOut(p);

    len=RAND_load_file(p,len);
    printf("\n\n\nload %d bytes from %s and adds them to the PRNG\n\n\n", len, p);

    ret=RAND_bytes(random, 20);
    if(ret == 1)
    {
        randomDataOut(random,20);
    }
    else
    {
        printf("RAND_bytes() fail:%ld\n", ERR_get_error());
    }

    RAND_cleanup();

}

// RAND_set_rand_method 设置自定义RAND_METHOD *meth，　可以生成自己的随机函数模块

int main(int argc, char const *argv[])
{
    rand_example();
    return 0;
}
