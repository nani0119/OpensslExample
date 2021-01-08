#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/bn.h>



void bn_2_xx()
{
    BIGNUM *a = NULL;
    char* num;
    int ret;
    printf("==========================================\n");
    //=======================================================
    char* dec = "1234567890";
    a = BN_new();

    // 将十进制字符串转换为大数
    ret = BN_dec2bn(&a, dec);

    // 将大数转化为十进制字符串返回
    num = BN_bn2dec(a);
    printf("bn 2 dec:\t%s\n", num);

    BN_clear(a);
    BN_free(a);

    //================================================================
    // 二进制数转换为大数, 非字符串
    unsigned char bin[4] = {0x49,  0x96, 0x02, 0xd2};
    a = BN_new();
    BN_bin2bn(bin, 4, a);

    // 大数转换为二进制数
    ret = BN_bn2bin(a, bin);
    printf("bn 2 bin:\t");
    for(int i = 0; i < ret; i++)
    {
        for(int j = 0; j < 8; j++)
        {
            printf("%s", ((bin[i] << j) & 0x80) ? "1": "0");
        }
    }
    printf("\n");

    BN_clear(a);
    BN_free(a);

    //=================================================================
    char* hex = "499602D2";
    a = BN_new();

    // 16进制字符串转换为大数
    BN_hex2bn(&a, hex);

    // 大数转换16进制字符串
    num = BN_bn2hex(a);
    printf("bn 2 hex:\t%s\n", num);
    

    BN_clear(a);
    BN_free(a);
}

void bn_dup()
{
    BIGNUM *a = NULL;
    BIGNUM *b;
    BIGNUM *c;
    BIGNUM *d;
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("==========================================\n");
    char* dec = "1234567890";
    a = BN_new();
    BN_dec2bn(&a, dec);
    BIO_printf(out, "a=");
    BN_print(out, a);
    BIO_printf(out, "\n");

    //=======================================================
    b = BN_new();
    BN_copy(b, a);

    BIO_printf(out, "b=");
    BN_print(out, b);
    BIO_printf(out, "\n");

    //=======================================================
    c = BN_dup(a);
    BIO_printf(out, "c=");
    BN_print(out, c);
    BIO_printf(out, "\n");

    //=======================================================
    d = BN_new();
    BN_swap(a, d);
    BIO_printf(out, "d=");
    BN_print(out, d);
    BIO_printf(out, "\n");


    BIO_printf(out, "a=");
    BN_print(out, a);
    BIO_printf(out, "\n");
    //=======================================================
    BIO_free(out);
    BN_free(c);
    BN_free(b);
    BN_free(a);
}

void bn_bit()
{
    BIGNUM* a;
    BIGNUM* r;
    char* dec;
    int i;
    int ret;
    printf("==========================================\n");
    r = BN_new();
    a = BN_new();

    for(i = 1; i <=128; i++)
    {
        if(i % 2 == 0)
        {
            BN_set_bit(a, i);
        }
        else
        {
            BN_clear_bit(a, i);
        }
        
    }

    dec = BN_bn2dec(a);
    printf("a=%s\n", dec);

    //=========================================================
    ret = BN_is_bit_set(a, 100);
    if(ret)
    {
        printf("bit 100 is setted\n");
    }
    else
    {
        printf("bit 100 is not setted\n");
    }
    
    //=========================================================
    BN_lshift1(r, a);
    dec = BN_bn2dec(r);
    printf("a=%s\n", dec);

    BN_rshift1(r, a);
    dec = BN_bn2dec(r);
    printf("a=%s\n", dec);


    BN_lshift(r, a, 1);
    dec = BN_bn2dec(r);
    printf("a=%s\n", dec);


    BN_rshift(r, a, 1);
    dec = BN_bn2dec(r);
    printf("a=%s\n", dec);
    //=========================================================

    // 截断至n位，假如a小于n位将出错
    BN_mask_bits(a, 8);
    dec = BN_bn2dec(a);
    printf("a=%s\n", dec);
    
    
    BN_free(a);
    BN_free(r);
}

void bn_op()
{
    char* dec = "1234567890";
    char* decnum;
    BIGNUM* a;
    const BIGNUM *b;
    BIGNUM* c;
    int bytes;
    int bits;
    int bits_word;
    printf("==========================================\n");
    a = BN_new();

    BN_dec2bn(&a, dec);

    bytes = BN_num_bytes(a);
    bits = BN_num_bits(a);
    //返回有意义比特的位数
    bits_word = BN_num_bits_word(1234567890);
    printf("%s: %d bytes, %d bits, %d bits_word\n", dec, bytes, bits, bits_word);
    //=========================================================

    BN_zero(a);
    decnum = BN_bn2dec(a);
    printf("a=%s\n", decnum);
    if(BN_is_zero(a))
    {
        printf("a is zeor\n");
    }

    BN_one(a);
    decnum = BN_bn2dec(a);
    printf("a=%s\n", decnum);
    if(BN_is_one(a))
    {
        printf("a is one\n");
    }

 
    //返回一个为1的大数
    b = BN_value_one(); 
    decnum = BN_bn2dec(b);
    printf("b=%s\n", decnum);

    //=========================================================
    BN_set_word(a, 9876543210); 
    decnum = BN_bn2dec(a);
    printf("a=%s\n", decnum);

    if(BN_is_word(a, 1234567890))
    {
        printf("a is word 1234567890\n");
    }
    else
    {
        printf("a is not word 1234567890\n");
    }
    
    if(BN_is_odd(a))
    {
        printf("a is odd\n");
    }
    else
    {
        printf("a is not odd\n");
    }
    

    // 假如大数a可以用一个long型表示，那么返回一个long型整数数
    printf("a=%ld\n", BN_get_word(a));
    //=========================================================


    c = BN_new();
    BN_dec2bn(&c, "-9876543210");
    decnum = BN_bn2dec(c);
    printf("c=%s\n", decnum);

    if(BN_cmp(a, c) == 0)
    {
        printf("a == c\n");
    }
    else
    {
        printf("a != c\n");
    }

    if(BN_ucmp(a, c) == 0)
    {
        printf("|a| == |c|\n");
    }
    else
    {
        printf("|a| != |c|\n");
    }
    

    BN_free(a);
    //BN_free(b);
    BN_free(c);

}


void bn_arithmetic_op()
{
    BIGNUM* a;
    BIGNUM* b;
    BIGNUM* m;
    BIGNUM* r;
    BIGNUM* rem;
    char* ret;
    BN_CTX *ctx;
    printf("==========================================\n");

    a = BN_new();
    b = BN_new();
    m = BN_new();
    r = BN_new();
    rem = BN_new();

    BN_dec2bn(&a, "1234567890");
    BN_copy(b, a);

    ret = BN_bn2dec(a);
    printf("a=%s\n", ret);

    ret = BN_bn2dec(b);
    printf("b=%s\n", ret);

    //======================================
    BN_add(r, a, b);
    ret = BN_bn2dec(r);
    printf("a+b=%s\n", ret);

    BN_sub(r, a, b);
    ret = BN_bn2dec(r);
    printf("a-b=%s\n", ret);


    ctx = BN_CTX_new();
    BN_mul(r, a, b, ctx);
    ret = BN_bn2dec(r);
    printf("a*b=%s\n", ret);
   // BN_CTX_free(ctx);

   //  ctx = BN_CTX_new();
    
    //rem = a % d
    BN_div(r,rem, a, b, ctx);
    ret = BN_bn2dec(r);
    printf("a/b=%s\n", ret);
    ret = BN_bn2dec(rem);
    printf("a mod b=%s\n", ret);

    //======================================

    BN_mod(rem, a, b, ctx);
    ret = BN_bn2dec(rem);
    printf("a mod b=%s\n", ret);

    BN_nnmod(r, a, b, ctx);
    ret = BN_bn2dec(r);
    printf("((a mod b)+b) mod b=%s\n", ret);


    BN_dec2bn(&m, "35");
    ret = BN_bn2dec(m);
    printf("m=%s\n", ret);

    BN_mod_add(r, a, b, m, ctx);
    ret = BN_bn2dec(r);
    printf("(a+b) mod m=%s\n", ret);


    BN_mod_sub(r, a, b, m, ctx);
    ret = BN_bn2dec(r);
    printf("(a-b) mod m=%s\n", ret);


    BN_mod_mul(r, a, b, m, ctx);
    ret = BN_bn2dec(r);
    printf("(a*b) mod m=%s\n", ret);

    BN_mod_sqr(r, a, m, ctx);
    ret = BN_bn2dec(r);
    printf("(a*a) mod m=%s\n", ret);
   
    //======================================

    BN_exp(r, a, m, ctx);
    ret = BN_bn2dec(r);
    printf("a^m=%s\n", ret);

    BN_mod_exp(r, a, m, b, ctx);
    ret = BN_bn2dec(r);
    printf("(a^m) mod b=%s\n", ret);

   //======================================
    // a和m 最大公约数
    BN_gcd(r, a, m, ctx);
    ret = BN_bn2dec(r);
    printf("gcd(a, m)=%s\n", ret);
   //======================================
    //取a对n取模的逆元存在r中, 即满足((r * a) % n) == 1的r的值
    BN_mod_inverse(r, a, m, ctx);
    ret = BN_bn2dec(r);
    printf("((%s*a) mod m) == 1\n", ret);
   //======================================


    BN_CTX_free(ctx);
    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(m);
    BN_free(rem);

}


void bn_rand()
{
    BIGNUM* rnd;
    BIGNUM* range;
    int bits;
    int top;
    int bottom;
    char* ret;
    printf("==========================================\n");
    range = BN_new();
    BN_dec2bn(&range, "1024");

    rnd = BN_new();
    // 产生一个加密用的强bits的伪随机数，
    // 若top=-1，最高位为0，top=0， 最高位为1，top=1,最高位和次高位为1，
    // bottom为真，随机数为偶数,否则奇偶随机
    bits = 10;
    top = 0;
    bottom = 1;
    BN_rand(rnd, bits, top, bottom);
    ret = BN_bn2dec(rnd);
    printf("rnd==%s\n", ret);

    bottom = 0;
    BN_pseudo_rand(rnd, bits, top, bottom);
    ret = BN_bn2dec(rnd);
    printf("pseudo rnd==%s\n", ret);


    // 0 < rnd < range
    BN_rand_range(rnd, range);
    ret = BN_bn2dec(rnd);
    printf("rnd==%s\n", ret);


    // 0 < rnd < range
    BN_pseudo_rand_range(rnd, range);
    ret = BN_bn2dec(rnd);
    printf("pseudo rnd==%s\n", ret);

    BN_free(rnd);
    BN_free(range);

}

void prime_cb(int a, int b, void * arg)
{
    //printf("========%s a %d b %d========\n", __func__, a, b);
}

void prime_check_cb(int a, int b, void *arg)
{
    //printf("========%s a %d b %d========\n", __func__, a, b);
}
void bn_prime()
{
    char* dec;
    BIGNUM* ret;
    BIGNUM *add = NULL;
    BIGNUM *rem = NULL;
    BIGNUM* r = NULL;
    int num;
    int safe;
    printf("==========================================\n");
    ret = BN_new();
    add = BN_new();
    rem = BN_new();
    BN_dec2bn(&add, "24680");
    BN_dec2bn(&rem, "13579");

    num = 64;
    safe = 1;
    //伪随机生成num位素数,如果ret返回值不为null,则用来储存答案,
    //如果add不是NULL，则prime将满足条件p％add == rem（p％add == 1 if rem == NULL）以适合给定的生成器。
    //如果safe是true,则生成的是一个安全的素数 (i.e. a prime p so that (p-1)/2 is also prime).
    r = BN_generate_prime(ret, num, safe, add, rem, prime_cb, NULL);
    if(r)
    {
        dec = BN_bn2dec(ret);
        printf("prime:%s\n", dec);
    }
    else
    {
        printf("not found prime\n");
    }

    //=====================================================
    int isPrime;
    BN_CTX *ctx;
    ctx = BN_CTX_new();
    int checks = 0;
    // 判断大数ret是否为素数,素数返回1,否则返回0,运算出错返回-1,错误概率小于 0.25^checks
    isPrime = BN_is_prime(ret, checks, prime_check_cb, ctx, NULL);
    if(isPrime)
    {
        printf("%s is prime\n", dec);
    }
    else
    {
        printf("%s is  not prime\n", dec);
    }
    
    //===============================================================
    int do_trial_divisio = 1;
    //当用do_trial_division == 1调用时，首先尝试通过一些小素数进行试验分割; 
    //如果此测试未找到除数且回调不为NULL，则调用回调（1，-1，cb_arg）。
    //如果do_trial_division == 0，则跳过此测试。
    isPrime = BN_is_prime_fasttest(ret, checks, prime_check_cb, ctx, NULL, do_trial_divisio);
    if(isPrime)
    {
        printf("%s is prime\n", dec);
    }
    else
    {
        printf("%s is  not prime\n", dec);
    }


    BN_CTX_free(ctx);
    
    BN_free(ret);
    BN_free(add);
    BN_free(rem);
}

void bn_set_negative()
{
    BIGNUM* a;
    char* dec = "123456789";
    printf("==========================================\n");

    a = BN_new();

    printf("a=%s\n", dec);
    BN_dec2bn(&a, dec);

    BN_set_negative(a, 1);
    printf("a=%s\n", BN_bn2dec(a));

    BN_free(a);

}

int main(int argc, char const *argv[])
{
    bn_2_xx();
    bn_dup();
    bn_bit();
    bn_op();
    bn_arithmetic_op();
    bn_rand();
    bn_prime();
    bn_set_negative();
    return 0;
}
