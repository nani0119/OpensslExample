#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs7err.h>
/*
加密消息语法（ pkcs7），是各种消息存放的格式标准。这些消息包括：数据、签名数据、
数字信封、签名数字信封、摘要数据和加密数据。
*/
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

void pkcs7_write_pem(char* name, PKCS7* p7)
{
    BIO* out = BIO_new_file(name, "w");
    PEM_write_bio_PKCS7(out, p7);
    BIO_free(out);
}

PKCS7* pkcs7_read_pem(char* name)
{
    BIO* in = BIO_new_file(name, "r");
    PKCS7* p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
    BIO_free(in);
    return p7;
}

void display_pkcs7_type(PKCS7* p7)
{
    printf("pkcs7 type:");
    if(p7 == NULL)
    {
        printf("\n");
        return;
    }
    switch(OBJ_obj2nid(p7->type))
    {
        case NID_pkcs7_data:
            printf("%s\n", LN_pkcs7_data);
            break;
        case NID_pkcs7_signed:
            printf("%s\n", LN_pkcs7_signed);
            break;
        case NID_pkcs7_enveloped:
            printf("%s\n", LN_pkcs7_enveloped);
            break;
        case NID_pkcs7_signedAndEnveloped:
            printf("%s\n", LN_pkcs7_signedAndEnveloped);
            break;
        case NID_pkcs7_digest:
            printf("%s\n", LN_pkcs7_digest);
            break;
        case NID_pkcs7_encrypted:
            printf("%s\n", LN_pkcs7_encrypted);
            break;
        default:
            printf("unknown pkcs7 type\n");
            break;
    }
}

//普通数据
void p7_data()
{
    char* data = "hello world";
    int datal = strlen(data);
    PKCS7 *p7;
    printf("===========================%s=========================\n", __func__);
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_data);
    ASN1_OCTET_STRING_set(p7->d.data, (unsigned char*)data, datal);
    pkcs7_write_pem("p7_data.pem", p7);
    PKCS7_free(p7);

    p7 = NULL;
    p7 = pkcs7_read_pem("p7_data.pem");
    display_pkcs7_type(p7);

    for(int i = 0; i < p7->d.data->length; i++)
    {
        printf("%c", (p7->d.data->data)[i]);
    }
    printf("\n");
}



void p7_signed_data()
{
    //PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,BIO *data, int flags)
    PKCS7 *p7;
    X509* x;
    X509_ALGOR* md;
    PKCS7_SIGNER_INFO *si;


    printf("===========================%s=========================\n", __func__);
    x509_generater();

    p7=PKCS7_new();
    PKCS7_set_type(p7,NID_pkcs7_signed);

    PKCS7_content_new(p7, NID_pkcs7_data);
    //PKCS7_set_detached(p7, 0);

    p7->d.sign->cert = sk_X509_new_null();

    BIO* in=BIO_new_file("x509.pem","r");
    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    PKCS7_add_certificate(p7, x);
    //sk_X509_push(p7->d.sign->cert,x);

    md=X509_ALGOR_new();
    md->algorithm=OBJ_nid2obj(NID_md5);
    sk_X509_ALGOR_push(p7->d.sign->md_algs,md);
  
    //pkey：签名者私钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* rin = BIO_new_file("RsaPrivate.pem", "r");
    RSA* rsaPri =PEM_read_bio_RSAPrivateKey(rin, NULL, mycb, "111111");
    EVP_PKEY_set1_RSA(pkey, rsaPri);
    si=PKCS7_add_signature(p7, x, pkey, EVP_md5());;
    ASN1_INTEGER_set(si->version,2);
    ASN1_INTEGER_set(si->issuer_and_serial->serial,1234567890);
    PKCS7_add_signer(p7, si);
    //sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info,si);
    
    BIO* p7bio = PKCS7_dataInit(p7, NULL);
    BIO_write(p7bio, "hello world", strlen("hello world"));
    PKCS7_dataFinal(p7, p7bio);

    pkcs7_write_pem("p7_signed_data.pem", p7);
    BIO_free(p7bio);
    //=============================================

    X509_free(x);
    //PKCS7_free(p7);
    //==============================================
//int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,BIO *indata, BIO *out, int flags)

    PKCS7 *p7r = pkcs7_read_pem("p7_signed_data.pem");
    display_pkcs7_type(p7);
    p7bio = PKCS7_dataDecode(p7r,NULL,NULL,NULL);
    char data[20] = {0};
    int datal = 20;
    BIO_read(p7bio,data,datal);
    printf("data:%s\n", data);

    STACK_OF(PKCS7_SIGNER_INFO) *sk = PKCS7_get_signer_info(p7r);
    int signCount = sk_PKCS7_SIGNER_INFO_num(sk);
    printf("signer count:%d\n", signCount);
    for(int i = 0; i < signCount; i++)
    {
        PKCS7_SIGNER_INFO *signInfo = sk_PKCS7_SIGNER_INFO_value(sk,i);
        X509 *cert= PKCS7_cert_from_signer_info(p7,signInfo);
        printf("sign info sn:%d\n", (signInfo->issuer_and_serial->serial)->data);
        if(PKCS7_signatureVerify(p7bio,p7r,signInfo,cert) != 1)
        {
            printf("signatureVerify fail\n");
        }
        else
        {
            printf("signatureVerify success\n");
        }
        
    }
}

void p7_enveloped()
{
    //int PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,int flags)
    PKCS7 *p7;
    X509* x;
    printf("===========================%s=========================\n", __func__);
    x509_generater();

    p7=PKCS7_new();
    PKCS7_set_type(p7,NID_pkcs7_enveloped);

    const EVP_CIPHER *cipher = EVP_des_cbc();
    PKCS7_set_cipher(p7, cipher);

    BIO* in=BIO_new_file("x509.pem","r");
    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    PKCS7_add_recipient(p7, x);


    BIO* p7bio = PKCS7_dataInit(p7, NULL);
    BIO_write(p7bio, "hello world", strlen("hello world"));
    BIO_flush(p7bio);
    PKCS7_dataFinal(p7, p7bio);

     pkcs7_write_pem("p7_enveloped.pem", p7);
//========================================================
    BIO_free_all(p7bio);
    PKCS7_free(p7);
//========================================================

    //PKCS7_decrypt

    PKCS7 *p7r;
    p7r = pkcs7_read_pem("p7_enveloped.pem");
    display_pkcs7_type(p7r);

    //pkey：签名者私钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* rin = BIO_new_file("RsaPrivate.pem", "r");
    RSA* rsaPri =PEM_read_bio_RSAPrivateKey(rin, NULL, mycb, "111111");
    EVP_PKEY_set1_RSA(pkey, rsaPri);

    p7bio = PKCS7_dataDecode(p7r,pkey,NULL,NULL);

    char data[20] = {0};
    int datal = 20;
    BIO_read(p7bio,data,datal);
    printf("data:%s\n", data);
    PKCS7_free(p7r);
    EVP_PKEY_free(pkey);

}

void p7_signed_and_enveloped()
{
    printf("===========================%s=========================\n", __func__);
}
//echo -n 'hello world' | md5sum -  
void p7_digest()
{
    PKCS7 *p7;
    printf("===========================%s=========================\n", __func__);
    p7=PKCS7_new();
    PKCS7_set_type(p7,NID_pkcs7_digest);
    PKCS7_content_new(p7, NID_pkcs7_data);
    PKCS7_set_digest(p7, EVP_md5());

    BIO* p7bio = PKCS7_dataInit(p7, NULL);
    BIO_write(p7bio, "hello world", strlen("hello world"));
    BIO_flush(p7bio);
    PKCS7_dataFinal(p7, p7bio);

     pkcs7_write_pem("p7_digest.pem", p7);


    BIO_free(p7bio);
    PKCS7_free(p7);
    //===============================================

    PKCS7 *p7r;
    p7r = pkcs7_read_pem("p7_digest.pem");
    display_pkcs7_type(p7r);

    unsigned char data[32] = {0};
    int datal = 32;
    int len = p7r->d.digest->digest->length;
    printf("datalen:%d digest:", len);
    for(int i = 0; i < len; i++)
    {
        printf("%02x", p7r->d.digest->digest->data[i]);
    }
    printf("\n");
    PKCS7_free(p7r);
}
//存放加过密的数据
void p7_encrypted()
{
    PKCS7 *p7;
    printf("===========================%s=========================\n", __func__);
    p7=PKCS7_new();
    PKCS7_set_type(p7,NID_pkcs7_encrypted);
    PKCS7_content_new(p7, NID_pkcs7_data);
    ASN1_INTEGER_set(p7->d.encrypted->version,3);
    p7->d.encrypted->enc_data->algorithm->algorithm=OBJ_nid2obj(NID_des_cbc);
    p7->d.encrypted->enc_data->enc_data=ASN1_OCTET_STRING_new();
    p7->d.encrypted->enc_data->cipher = EVP_des_cbc();
    //存放加过密的数据
    ASN1_OCTET_STRING_set(p7->d.encrypted->enc_data->enc_data,(const unsigned char *)"hello world", strlen("hello world"));
    pkcs7_write_pem("p7_encrypted.pem", p7);



    PKCS7_free(p7);
//=================================================
    PKCS7 *p7r;
    p7r = pkcs7_read_pem("p7_encrypted.pem");
    display_pkcs7_type(p7r);

    printf("%s\n",p7r->d.encrypted->enc_data->enc_data->data);

    PKCS7_free(p7r);
}



int main(int argc, char const *argv[])
{
    p7_data();
    p7_signed_data();
    p7_enveloped();
    p7_signed_and_enveloped();
    p7_digest();
    p7_encrypted();
    return 0;
}
