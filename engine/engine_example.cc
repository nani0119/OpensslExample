#include <stdlib.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/rc4.h>

// engine/eng_openssl.c

static const char *engine_id = "hw_engine";
static const char *engine_name = "hw engine example";

void print_bin(unsigned char* tag ,unsigned char* data, int len)
{
    printf("%s: ", tag);
    for(int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");

}

//========================================================================
static int hw_get_random_bytes(unsigned char *buf, int num)
{
    int i;
    printf("------------%s---------------\n", __func__);
    for (i = 0; i < num; i++)
        memset(buf++, rand() % 255, 1);
    return 1;
}
/* 随机数方法 */
static RAND_METHOD hw_engine_rand ={
    NULL,
    hw_get_random_bytes,
    NULL,
    NULL,
    NULL,
    NULL,
};
//======================================================================
/** SHA1 implementation */
static int hw_engine_sha1_init(EVP_MD_CTX* ctx)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Init((SHA_CTX*)EVP_MD_CTX_md_data(ctx));
    return 1;
}

static int hw_engine_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Update((SHA_CTX*)EVP_MD_CTX_md_data(ctx), data, count);
    return 1;
}

static int hw_engine_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Final(md, (SHA_CTX*)EVP_MD_CTX_md_data(ctx));
    return 1;
}

static EVP_MD *hw_engine_sha1 = NULL;
static EVP_MD *hw_engine_digest_sha1()
{
    printf("------------%s---------------\n", __func__);
    if (hw_engine_sha1 == NULL)
    {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL 
                || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH) 
                || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK) 
                || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SHA_CTX)) 
                || !EVP_MD_meth_set_flags(md, 0) 
                || !EVP_MD_meth_set_init(md, hw_engine_sha1_init) 
                || !EVP_MD_meth_set_update(md, hw_engine_sha1_update) 
                || !EVP_MD_meth_set_final(md, hw_engine_sha1_final))
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        hw_engine_sha1 = md;
    }
    return hw_engine_sha1;
}


static void hw_engine_sha1_destroy()
{
    printf("------------%s---------------\n", __func__);
    EVP_MD_meth_free(hw_engine_sha1);
    hw_engine_sha1 = NULL;
}

static int digest_nids[] = {NID_sha1, 0};

int digest_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    int ok = 1;
    printf("------------%s---------------\n", __func__);
    if (!digest)
    {
        /* expected to return the list of supported NIDs */
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }

    /** Request for a specific digest */
    switch (nid)
    {
    case NID_sha1:
        *digest = hw_engine_digest_sha1();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}
//=================================================================

typedef struct {
    unsigned char key[16];
    RC4_KEY ks;
} TEST_RC4_KEY;

# define test(ctx) ((TEST_RC4_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int hw_engine_cipher_rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    printf("------------%s---------------\n", __func__);
    memcpy(&test(ctx)->key[0], key, EVP_CIPHER_CTX_key_length(ctx));
    RC4_set_key(&test(ctx)->ks, EVP_CIPHER_CTX_key_length(ctx),test(ctx)->key);
    return 1;
}

static int hw_engine_cipher_rc4(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    printf("------------%s---------------\n", __func__);
    RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}


static EVP_CIPHER *hw_engine_r4 = NULL;
static const EVP_CIPHER *hw_engine_cipher_r4(void)
{
    printf("------------%s---------------\n", __func__);
    if (hw_engine_r4 == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = EVP_CIPHER_meth_new(NID_rc4, 1, 16)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !EVP_CIPHER_meth_set_init(cipher, hw_engine_cipher_rc4_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(cipher, hw_engine_cipher_rc4)
            || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_RC4_KEY))) {
            EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        hw_engine_r4 = cipher;
    }
    return hw_engine_r4;
}

static void hw_engine_r4_destroy(void)
{
    printf("------------%s---------------\n", __func__);
    EVP_CIPHER_meth_free(hw_engine_r4);
    hw_engine_r4 = NULL;
}


static EVP_CIPHER *hw_engine_r4_40 = NULL;
static const EVP_CIPHER *hw_engine_cipher_r4_40(void)
{
    printf("------------%s---------------\n", __func__);
    if (hw_engine_r4_40 == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = EVP_CIPHER_meth_new(NID_rc4, 1, 5 /* 40 bits */)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !EVP_CIPHER_meth_set_init(cipher, hw_engine_cipher_rc4_init_key)
            || !EVP_CIPHER_meth_set_do_cipher(cipher, hw_engine_cipher_rc4)
            || !EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_RC4_KEY))) {
            EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        hw_engine_r4_40 = cipher;
    }
    return hw_engine_r4_40;
}

static void hw_engine_r4_40_destroy(void)
{
    printf("------------%s---------------\n", __func__);
    EVP_CIPHER_meth_free(hw_engine_r4_40);
    hw_engine_r4_40 = NULL;
}

static int cipher_nids[] = {NID_rc4, NID_rc4, 0};
static int ciphers_selector(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    int ok = 1;
    printf("------------%s---------------\n", __func__);
    if (!cipher)
    {
        /* expected to return the list of supported NIDs */
        *nids = cipher_nids;
        return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
    }

    switch (nid)
    {
    case NID_rc4:
        *cipher = hw_engine_cipher_r4();
        break;
    case NID_rc4_40:
        *cipher = hw_engine_cipher_r4_40();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}
//=================================================================
static EVP_PKEY *hw_engine_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    printf("------------%s---------------\n", __func__);
    BIO *in;
    EVP_PKEY *key;
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    return key;;
}

static EVP_PKEY *hw_engine_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    printf("------------%s---------------\n", __func__);
    BIO *in;
    EVP_PKEY *key;
    in = BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = PEM_read_bio_PUBKEY(in, NULL, NULL, NULL);
    BIO_free(in);
    return key;;
}
//========================================================================
/* 生成 RSA 密钥对 */
static int hw_engine_genrete_rsa_key(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    printf("------------%s---------------\n", __func__);
    return RSA_generate_key_ex(rsa, bits, e, cb);
}
/* RSA 公钥加密 */
static int hw_engine_rsa_pub_enc(int flen,const unsigned char *from,unsigned char *to,RSA *rsa,int padding)
{
    printf("------------%s---------------\n", __func__);
    return RSA_public_encrypt(flen, from, to, rsa, padding);
}
/*RSA 公钥解密 */
static int hw_engine_rsa_pub_dec(int flen,const unsigned char *from,unsigned char *to,RSA *rsa,int padding)
{
    printf("------------%s---------------\n", __func__);
    return RSA_public_decrypt(flen, from, to, rsa, padding);
}

/* RSA 私钥加密 */
static int hw_engine_rsa_priv_enc(int flen,const unsigned char *from,unsigned char *to,RSA *rsa,int padding)
{
    printf("------------%s---------------\n", __func__);
    return RSA_private_encrypt(flen, from, to, rsa, padding);
}

static int hw_engine_rsa_priv_dec(int flen,const unsigned char *from,unsigned char *to,RSA *rsa,int padding)
{
    printf("------------%s---------------\n", __func__);
    return RSA_private_decrypt(flen, from, to, rsa, padding);
}

static int hw_engine_rsa_free(RSA* r)
{
    printf("------------%s---------------\n", __func__);
    RSA_free(r);
    return 1;
}

RSA_METHOD* hw_engine_rsa = NULL;
static RSA_METHOD* hw_engine_rsa_method()
{
    RSA_METHOD* m;
    if(hw_engine_rsa == NULL)
    {
        m = RSA_meth_new("hw engine rsa method", 0);
        if (    m== NULL
                || !RSA_meth_set_pub_enc(m, hw_engine_rsa_pub_enc)
                || !RSA_meth_set_pub_dec(m,hw_engine_rsa_pub_dec)
                || !RSA_meth_set_priv_enc(m, hw_engine_rsa_priv_enc)
                || !RSA_meth_set_priv_dec(m, hw_engine_rsa_priv_dec)
                || !RSA_meth_set_mod_exp(m,RSA_meth_get_mod_exp(RSA_get_default_method()))
                || !RSA_meth_set_bn_mod_exp(m,RSA_meth_get_bn_mod_exp(RSA_get_default_method()))
                || !RSA_meth_set_finish(m, hw_engine_rsa_free)
                || !RSA_meth_set_sign(m, RSA_meth_get_sign(RSA_get_default_method()))
                || !RSA_meth_set_verify(m, RSA_meth_get_verify(RSA_get_default_method())))
            {
                RSA_meth_free(m);
                m = NULL;
            }
        
    }
    hw_engine_rsa = m;
    return hw_engine_rsa;
}

static void hw_engine_rsa_destroy(void)
{
    printf("------------%s---------------\n", __func__);
    RSA_meth_free(hw_engine_rsa);
    hw_engine_rsa = NULL;
}
//========================================================================
static int hw_engine_init(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    return 1;
}

static int hw_engine_destroy(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    hw_engine_sha1_destroy();
    hw_engine_r4_destroy();
    hw_engine_r4_40_destroy();
    hw_engine_rsa_destroy();
    return 1;
}

static int hw_engine_finish(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    return 0;
}

#define HW_SET_RSA_PRIVATE_KEY 1
#define HW_SET_RSA_PUBLIC_KEY  2
/* 实现自己的控制函数 */
static int hw_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    printf("------------%s---------------\n", __func__);
    switch (cmd)
    {
    case HW_SET_RSA_PRIVATE_KEY:
        hw_engine_load_privkey(e, p, NULL, NULL);
        break;
    case HW_SET_RSA_PUBLIC_KEY:
        hw_engine_load_pubkey(e, p, NULL, NULL);
        break;
    default:
        printf("err.\n");
        return -1;
    }
    return 0;
}

static const ENGINE_CMD_DEFN hw_engine_cmd_defns[] = {
    {ENGINE_CMD_BASE, "SO_PATH", "Specifies the path to the 'hw' shared library", ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

static int bind_engine_helper(ENGINE *e, const char *id)
{
    int ret = 0;
    printf("------------%s---------------\n", __func__);
    if (!ENGINE_set_id(e, id))
    {
        printf("ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_name))
    {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    if (!ENGINE_set_destroy_function(e, hw_engine_destroy))
    {
        printf("ENGINE_set_destroy_function failed\n");
        goto end;
    }

    if (!ENGINE_set_init_function(e, hw_engine_init))
    {
        printf("ENGINE_set_init_function failed\n");
        goto end;
    }

    if (!ENGINE_set_finish_function(e, hw_engine_finish))
    {
        printf("ENGINE_set_finish_function failed\n");
        goto end;
    }

    if (!ENGINE_set_ctrl_function(e, hw_engine_ctrl))
    {
        printf("ENGINE_set_ctrl_function failed\n");
        goto end;
    }

    if (!ENGINE_set_load_privkey_function(e, hw_engine_load_privkey))
    {
        printf("ENGINE_set_load_privkey_function failed\n");
        goto end;
    }

    if (!ENGINE_set_load_pubkey_function(e, hw_engine_load_pubkey))
    {
        printf("ENGINE_set_load_pubkey_function failed\n");
        goto end;
    }

    if (!ENGINE_set_cmd_defns(e, hw_engine_cmd_defns))
    {
        printf("ENGINE_set_cmd_defns failed\n");
        goto end;
    }

    // rsa
    if (!ENGINE_set_RSA(e, hw_engine_rsa_method()))
    {
        printf("ENGINE_set_RSA failed\n");
        goto end;
    }
    // dsa
    if(!ENGINE_set_DSA(e, DSA_get_default_method()))
    {
        printf("ENGINE_set_DSA failed\n");
        goto end;
    }

    if(!ENGINE_set_EC(e, EC_KEY_OpenSSL()))
    {
        printf("ENGINE_set_EC failed\n");
        goto end; 
    }

    if(!ENGINE_set_DH(e, DH_get_default_method()))
    {
        printf("ENGINE_set_DH failed\n");
        goto end; 
    }
    
    if (!ENGINE_set_RAND(e, &hw_engine_rand))
    {
        printf("ENGINE_set_digest failed\n");
        goto end;
    }

    if (!ENGINE_set_digests(e, digest_selector))
    {
        printf("ENGINE_set_digest failed\n");
        goto end;
    }

    if(!ENGINE_set_ciphers(e, ciphers_selector))
    {
        printf("ENGINE_set_ciphers failed\n");
        goto end;         
    }

    if(!ENGINE_set_load_privkey_function(e, hw_engine_load_privkey))
    {
        printf("ENGINE_set_load_privkey_function failed\n");
        goto end;           
    }
    if(!ENGINE_set_load_pubkey_function(e, hw_engine_load_pubkey))
    {
        printf("ENGINE_set_load_pubkey_function failed\n");
        goto end;  
    }
    
    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_engine_helper)


static ENGINE *hw_engine(void)
{
    ENGINE *e = ENGINE_new();
    printf("------------%s---------------\n", __func__);
    if (!e)
        return NULL;
    if (!bind_engine_helper(e, engine_id))
    {
        ENGINE_free(e);
        return NULL;
    }
    return e;
}

void load_hw_engine()
{
    ENGINE *e_hw = hw_engine();
    printf("------------%s---------------\n", __func__);
    if (!e_hw)
        return;
    ENGINE_add(e_hw);
    ENGINE_free(e_hw);
    ERR_clear_error();
}

void rsa_gen_key_enc_dec()
{
    int ret = 0;
    RSA* rsaParis;
    RSA* rsaPublic;
    RSA* rsaPrivate;
    BIGNUM* e;
    int bits = 512;
    char* plain="hello world";
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
    rsaPublic = RSAPublicKey_dup(rsaParis);
    cipperlen = RSA_public_encrypt(plainlen, plain, cipper, rsaPublic, RSA_PKCS1_OAEP_PADDING);
    print_bin("rsa en",cipper, cipperlen);
    printf("----------------------------------------\n");
    // 私钥解密
    rsaPrivate = RSAPrivateKey_dup(rsaParis);

    newplainlen = RSA_private_decrypt(cipperlen, cipper, newplain, rsaPrivate, RSA_PKCS1_OAEP_PADDING);
    printf("rsa den: %s\n", newplain);

    RSA_free(rsaParis);
    RSA_free(rsaPublic);
    RSA_free(rsaPrivate);
    BN_free(e);
}

void rsa_sign_verify()
{
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

    // ==================================
    // 计算摘要
    MD5(data, strlen(data), md);

    //======================================
    // 私钥签名
    ret = RSA_sign(NID_sha1, md, 16, sigret, &sigretlen, rsaPrivate);
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
    ret = RSA_verify(NID_sha1, md, 16, sigret, sigretlen, rsaPublic);
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
    ENGINE* e = NULL;
    char* in = "hello world";
    int inlen = strlen(in);
    unsigned char out[128] = {0};
    unsigned int outlen = 128;
    char* name;
    OpenSSL_add_all_algorithms();
    load_hw_engine();
    e = ENGINE_by_id(engine_id);
    if(e == NULL)
    {
        printf("failed to retrieve engine by id :%s\n", engine_id);
        return 1;
    }

    name = (char *)ENGINE_get_name(e);
    printf("engine name :%s \n",name);
    //===========================================================
#if 0
    unsigned char rand_buf[16] = {0};
    int rand_len = 16;
    RAND_set_rand_engine(e);
    RAND_bytes((unsigned char *)rand_buf,rand_len);
    printf("rand data:");
    for(int i = 0; i < rand_len; i++)
    {
        printf("%02x ", rand_buf[i]);
    }
    printf("\n");
#endif
#if 0
    const EVP_MD* md = EVP_sha1();
    EVP_add_digest(EVP_sha1());
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, e);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    print_bin("sha1",out, outlen);
    EVP_MD_CTX_free(ctx);
#endif
    //===============================================================
#if 0
    unsigned char r4out[EVP_MAX_BLOCK_LENGTH+inlen] = {0};
    unsigned char* r4outtmp = r4out;
    int r4outlen = EVP_MAX_BLOCK_LENGTH + inlen;
    int total = 0;

    unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};

    const EVP_CIPHER* cipher = EVP_rc4();
    EVP_add_cipher(cipher);
    EVP_BytesToKey(cipher, EVP_sha1(), NULL, "passwd", 6, 3, key, iv);

    EVP_CIPHER_CTX* cipher_en_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_en_ctx);

    EVP_EncryptInit_ex(cipher_en_ctx, cipher, e, key, iv);
    EVP_EncryptUpdate(cipher_en_ctx, r4outtmp, &r4outlen, in, inlen);
    total += r4outlen;
    r4outtmp += r4outlen;
    EVP_EncryptFinal_ex(cipher_en_ctx, r4outtmp, &r4outlen);
    total += r4outlen;
    print_bin("rc enc", r4out, total);

    EVP_CIPHER_CTX_free(cipher_en_ctx);
    //------------------------------------------------------------------------
    unsigned char r4data[EVP_MAX_BLOCK_LENGTH+inlen] = {0};
    int r4datalen = EVP_MAX_BLOCK_LENGTH+inlen;

    unsigned char* r4datatmp = r4data;
    int r4datatotal = 0;

    EVP_CIPHER_CTX* cipher_de_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(cipher_de_ctx);

    EVP_DecryptInit_ex(cipher_de_ctx, cipher, NULL, key, iv);
    EVP_DecryptUpdate(cipher_de_ctx, r4datatmp, &r4datalen, r4out, total);
    r4datatotal += r4datalen;
    r4datatmp += r4datalen;
    EVP_DecryptFinal_ex(cipher_de_ctx, r4datatmp, &r4datalen);
    r4datatotal += r4datalen;

    printf("%s\n", r4data);
    EVP_CIPHER_CTX_free(cipher_de_ctx);
#endif
//==================================================================================
#if 1
    rsa_gen_key_enc_dec();
    printf("-------------------------------------------------\n");
    rsa_sign_verify();
#endif
//===================================================================================

    ENGINE_finish(e);
    return 0;
}
