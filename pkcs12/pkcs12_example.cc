#include <stdio.h>
#include <string.h>

#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int mycb(char* passwd, int num, int flag, char* key)
{
    printf("====================%s:%s==================\n",__func__, key);
    if(key)
    {
        strcpy(passwd, key);
    }
    else
    {
        if(flag == 1)
        {
            printf("please input passwd for encrypt:");
        }
        else
        {
            printf("please input passwd for decrypt:");
        }
        scanf("%s", passwd);
    }
    return strlen(passwd);
}


void x509_generater()
{
    X509 *x;
    x=X509_new();

    // version
    X509_set_version(x,0x02);

    // SN
    ASN1_INTEGER *sn = ASN1_INTEGER_new();
    ASN1_INTEGER_set_uint64(sn, 1234567890);
    X509_set_serialNumber(x, sn);

    //signature algorithm
    

    //issuer
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_UTF8STRING, "Root Agencys", -1 , -1, 0);
    X509_set_issuer_name(x,name);

    //Time
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter (x), 60*60*24*365);

    // subject
    X509_set_subject_name(x, name);

    // public key
    RSA* rsa=RSA_generate_key(1024, RSA_3, NULL, NULL);
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_set_pubkey(x,pkey);

    // signature
    X509_sign(x, pkey, EVP_md5());

    BIO* file = BIO_new_file("RsaPrivate.pem", "w");
    PEM_write_bio_RSAPrivateKey(file, rsa, EVP_des_cbc(), "111111", 6, NULL, NULL);
    BIO_free(file);

    file = BIO_new_file("x509.pem", "w");
    PEM_write_bio_X509(file, x);
    BIO_free(file);

    EVP_PKEY_free(pkey);
    X509_NAME_free(name);
    ASN1_INTEGER_free(sn);
    X509_free(x);
}

/*包含私钥和证书*/
void p12_gen()
{
    PKCS12* p12 = NULL;
    PKCS7*  p7  = NULL;
    X509 *cert=NULL;
    EVP_PKEY *pkey=NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    PKCS12_SAFEBAG *bag;
    STACK_OF(PKCS7) *safes;

    OpenSSL_add_all_algorithms();
    x509_generater();
    printf("=============================%s==========================\n",__func__);

    p12=PKCS12_init(NID_pkcs7_data);

    bags=sk_PKCS12_SAFEBAG_new_null();

    /* cert */
    BIO* bio_in_x509=BIO_new_file("x509.pem","r");
    cert = PEM_read_bio_X509(bio_in_x509, NULL, NULL, NULL);
    bag=PKCS12_x5092certbag(cert);
    sk_PKCS12_SAFEBAG_push(bags,bag);
    BIO_free(bio_in_x509);

    /* 私钥 */
    pkey = EVP_PKEY_new();
    BIO* rin = BIO_new_file("RsaPrivate.pem", "r");
    RSA* rsaPri =PEM_read_bio_RSAPrivateKey(rin, NULL, mycb, "111111");
    EVP_PKEY_set1_RSA(pkey, rsaPri);
    BIO_free(rin);
    PKCS12_add_key(&bags,pkey,KEY_EX,PKCS12_DEFAULT_ITER,NID_pbeWithMD5AndDES_CBC,"654321");


    p7=PKCS12_pack_p7data(bags);

    safes=sk_PKCS7_new_null();
    sk_PKCS7_push(safes,p7);

    PKCS12_pack_authsafes(p12,safes);

    PKCS12_set_mac(p12, "654321", -1, NULL, 0, -1, EVP_md5());

    int len=i2d_PKCS12(p12,NULL);
    unsigned char* buf =(unsigned char*) OPENSSL_malloc(len);
    unsigned char* p = buf;
    len=i2d_PKCS12(p12,&p);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* out = BIO_new_file("p12_pkey_cert.pfx", "w");
    BIO_push(b64, out);
    BIO_write(b64, buf, len);
    BIO_flush(b64);
    BIO_free_all(b64);
    OPENSSL_free(buf);
}

void evp_pkey_info(EVP_PKEY *pkey)
{
    printf("PKEY name:\t%s\n", OBJ_nid2ln(EVP_PKEY_type(EVP_PKEY_base_id(pkey))));
    printf("PKEY size:\t%d\n", EVP_PKEY_size(pkey));
    printf("PKEY bits:\t%d\n", EVP_PKEY_bits(pkey));
}
void p12_load()
{
    PKCS12* p12 = NULL;
    EVP_PKEY *pkey=NULL;
    X509 *cert=NULL;
    unsigned char buf[2048] = {0};
    unsigned char pkey_out[1024] = {0};
    int pkey_outl = 1024;
    OpenSSL_add_all_algorithms();

    printf("=============================%s==========================\n",__func__);
    BIO* in = BIO_new_file("p12_pkey_cert.pfx", "r");
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, in);
    int len = BIO_read(b64, buf, 2048);
    const unsigned char* p = buf;
    p12 = d2i_PKCS12(NULL, &p, len);
    if(p12 != NULL)
    {
        printf("d2i pkcs12 success\n");
    }
    else
    {
        printf("d2i pkcs12 fail\n");
    }
    
    BIO_free_all(b64);
#if 1
    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
    {
        printf("empty password\n");
    }
    else
    {
        printf("not empty password\n");
        if (!PKCS12_verify_mac(p12, "654321", 6))
        {
            printf("verfy mac fail\n");
        }
        else
        {
            printf("verfy mac success\n");
        }
    }
#endif
    int ret = PKCS12_parse(p12, "654321", &pkey, &cert, NULL);
    if(ret != 1)
    {
        char estring[1024] = {0};
        ERR_error_string(ERR_get_error(), estring);
        printf("PKCS12_parse fail: %s\n", estring);
    }
    else
    {
        printf("PKCS12_parse success\n");
    }
    printf("-----------------------------------------------------------------------\n");
    //================================================
    printf("cert version:\t %d\n", X509_get_version(cert));
    printf("cert sn:\t %d\n", ASN1_INTEGER_get(X509_get_serialNumber(cert)));
    printf("-----------------------------------------------------------------------\n");

    EVP_PKEY_CTX* ctx;
    EVP_PKEY* pubPkey = X509_get0_pubkey(cert);
    evp_pkey_info(pubPkey);
    printf("-----------------------------------------------------------------------\n");
    unsigned char d[1024] = {0};
    size_t dlen = 1024;
    ctx = EVP_PKEY_CTX_new(pubPkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_encrypt(ctx, pkey_out,(size_t*) &pkey_outl, "hello world", strlen("hello world"));
    printf("encrypt out len:%d\n", pkey_outl);
    printf("enc data:");
    for(int i = 0; i < pkey_outl; i++)
    {
        printf("%02x", pkey_out[i]);
    }
    printf("\n");
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    printf("-----------------------------------------------------------------------\n");
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    ret = EVP_PKEY_decrypt(ctx, d, &dlen, pkey_out, pkey_outl);
    if(ret != 1)
    {
        char estring[1024] = {0};
        ERR_error_string(ERR_get_error(), estring);
        printf("PKCS12_parse fail: %s\n", estring);;
    }
    evp_pkey_info(pkey);
    printf("-----------------------------------------------------------------------\n");
    printf("dlen:%d\n", dlen);
    printf("%s\n", d);
    printf("-----------------------------------------------------------------------\n");
    EVP_PKEY_CTX_free(ctx);
}

int main(int argc, char const *argv[])
{
    ERR_load_PKCS12_strings();
    p12_gen();
    p12_load();
    ERR_free_strings();
    return 0;
}
