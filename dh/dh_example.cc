#include <stdlib.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/bio.h>

// A和B都知道的大数（g, p）
// A生成一个在[1, p-1]之间的随机数a作为私钥  Pa = g^a mod p  作为公钥， 发送Pa 给B
// B生成一个在[1, p-1]之间的随机数b作为私钥  Pb = g^b mod p  作为公钥， 发送Pb 给A
// A、B根据对方发送过来的公钥计算对称秘钥， Ka = Pb^a mod p = (g^b)^a mod p = g^(ab) mod p, Kb = Pa^b mod n = (g^a)^b mod p = g^(ab) mod p 
// Ka = Kb 为对称秘钥，其他人可以知道 p、 g、 Pa 和 Pb，但是他们不能计算出密钥，除非他们能恢复 a 或者 b, 但是计算a或者b， 需要进行对数运算，复杂度高

DH* dh_a_gen()
{
    DH* da;
    int ret;
    int codes;
    int prime_len = 512;

    da = DH_new();
    /* 生成 da 的密钥参数，该密钥参数是可以公开的 */
    ret = DH_generate_parameters_ex(da, prime_len, DH_GENERATOR_2, NULL);
    if(ret != 1)
    {
        printf("DH_generate_parameters_ex err!\n");
        goto end;
    }

    ret = DH_check(da, &codes);
    if (ret != 1)
    {
        printf("DH_check err!\n");
        if (codes & DH_CHECK_P_NOT_PRIME)
            printf("p value is not prime\n");
        if (codes & DH_CHECK_P_NOT_SAFE_PRIME)
            printf("p value is not a safe prime\n");
        if (codes & DH_UNABLE_TO_CHECK_GENERATOR)
            printf("unable to check the generator value\n");
        if (codes & DH_NOT_SUITABLE_GENERATOR)
            printf("the g value is not a generator\n");

        goto end;
    }
    

    printf("DH size:%d\n", DH_size(da));

    /* 生成公私钥 */
    DH_generate_key(da);

    /* 检查公钥 */
    ret = DH_check_pub_key(da, DH_get0_pub_key(da), &codes);
    if (ret != 1)
    {
        if (codes & DH_CHECK_PUBKEY_TOO_SMALL)
            printf("pub key too small \n");
        if (codes & DH_CHECK_PUBKEY_TOO_LARGE)
            printf("pub key too large \n");
    }
    return da;
end:
    printf("gen dh a fail\n");
    return NULL;
}

int main(int argc, char const *argv[])
{
    DH* b;
    unsigned char Ka[128] = {0};
    unsigned char Kb[128] = {0};
    DH* a = dh_a_gen();
    if(a == NULL)
    {
        return;
    }
    b = DH_new();

    /* p 和 g 为公开的密钥参数，因此可以拷贝 */
    DH_set0_pqg(b, BN_dup(DH_get0_p(a)), NULL, BN_dup(DH_get0_g(a)));
    /* 生成公私钥 */
    DH_generate_key(b);

    //计算共享密钥
    int alen = DH_compute_key(Ka, DH_get0_pub_key(b), a);
    int blen = DH_compute_key(Kb, DH_get0_pub_key(a), b);
    if (alen != blen)
    {
        printf("DH_compute_key fail 1\n");
        goto end;
    }
    if (memcmp(Ka, Kb, alen) != 0)
    {
        printf("H_compute_key fail 2\n");
        goto end;
    }
    else
    {
        printf("H_compute_key success\n");
    }
    
    printf("------------------------------------------------\n");
    //==================================================
    BIO* bio=BIO_new(BIO_s_file());
    BIO_set_fp(bio,stdout,BIO_NOCLOSE);
    DHparams_print(bio, a);
    printf("------------------------------------------------\n");
    DHparams_print(bio, b);
    BIO_free(bio);

end:
    DH_free(a);
    DH_free(b);
    return 0;
}
