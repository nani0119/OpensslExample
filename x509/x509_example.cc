#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>

typedef struct seq_x509
{
    X509_ALGOR alg;

} SEQ_X509;

//　指明如何生成SEQ_X509以及如何ASN1编码，　X509_ALGOR类似，但是openssl库已经提前定义好了
ASN1_SEQUENCE(SEQ_X509) = {
        ASN1_EMBED(SEQ_X509, alg, X509_ALGOR)
} 
ASN1_SEQUENCE_END(SEQ_X509)

DECLARE_ASN1_FUNCTIONS(SEQ_X509)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_X509)

int store_SEQ_X509()
{
    printf("==============================%s==============================\n",__func__);
    BIO *fbio = BIO_new_file("x509.der", "w");
    char* data = "hello world";

    SEQ_X509* x509 = SEQ_X509_new();


    x509->alg.algorithm=OBJ_nid2obj(NID_sha256);
    x509->alg.parameter=ASN1_TYPE_new();
    ASN1_TYPE_set_octetstring(x509->alg.parameter, data, strlen(data));

    int len = i2d_SEQ_X509(x509, NULL);
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    len = i2d_SEQ_X509(x509, &p);
    
    BIO_write(fbio, alg_buf, len);
    BIO_flush(fbio);

    OPENSSL_free(alg_buf);
    //X509_ALGOR_free(x509->alg);
    SEQ_X509_free(x509);
    BIO_free(fbio);
    return len;
}

void load_SEQ_X509(int len)
{
    printf("==============================%s==============================\n",__func__);
    BIO *fbio = BIO_new_file("x509.der", "r");
    char data[]={"hello world"};
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    BIO_read(fbio, alg_buf, len);

    SEQ_X509* x509 = SEQ_X509_new();
    //x509->alg = X509_ALGOR_new();
    d2i_SEQ_X509(&x509, &p, len);

    if(OBJ_obj2nid(x509->alg.algorithm) == NID_sha256)
    {
        printf("algorithm:NID_sha256\n");
        memset(data, 0, sizeof(data));
        ASN1_TYPE_get_octetstring(x509->alg.parameter, data, sizeof(data));
        printf("parameter:%s\n", data);
    }
    OPENSSL_free(alg_buf);
    //X509_ALGOR_free(x509->alg);
    SEQ_X509_free(x509);
    BIO_free(fbio);
}

void x509_alg()
{
    printf("==============================%s==============================\n",__func__);
    char data[]={"hello world"};

    BIO *fbio = BIO_new_file("algor.der", "w");

    X509_ALGOR *alg = X509_ALGOR_new();
    ASN1_OBJECT* alg_obj= OBJ_nid2obj(NID_sha256);
    //X509_ALGOR_set0(alg, alg_obj, V_ASN1_OCTET_STRING, data);
    alg->algorithm=OBJ_nid2obj(NID_sha256);
    alg->parameter=ASN1_TYPE_new();
    ASN1_TYPE_set_octetstring(alg->parameter, data, strlen(data));

    int len = i2d_X509_ALGOR(alg, NULL);
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    len = i2d_X509_ALGOR(alg, &p);

    BIO_write(fbio, alg_buf, len);
    BIO_flush(fbio);


    OPENSSL_free(alg_buf);
    X509_ALGOR_free(alg);
    BIO_free(fbio);
    //========================================================================
    fbio = BIO_new_file("algor.der", "r");
    alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    p = alg_buf;
    X509_ALGOR *alg_dup = X509_ALGOR_new();
    BIO_read(fbio, alg_buf, len);
    d2i_X509_ALGOR(&alg_dup,&p,len);

    if(OBJ_obj2nid(alg_dup->algorithm) == NID_sha256)
    {
        printf("algorithm:NID_sha256\n");
        memset(data, 0, sizeof(data));
        ASN1_TYPE_get_octetstring(alg_dup->parameter, data, sizeof(data));
        printf("parameter:%s\n", data);
    }
    X509_ALGOR_free(alg_dup);
    BIO_free(fbio);
    OPENSSL_free(alg_buf);
}

void x509_val()
{
    printf("==============================%s==============================\n",__func__);
    //数据结构用来表示有效时间
    X509_VAL *val = X509_VAL_new();
    time_t t = time(0);

    ASN1_TIME_set(val->notBefore, t);
    ASN1_TIME_set(val->notAfter, t+1000);
    //i2d_X509_VAL(val,&p)
    //d2i_X509_VAL(val,&p,len);
    X509_VAL_free(val);
}

void x509_sig()
{
    printf("==============================%s==============================\n",__func__);
    unsigned char *buf,*p;
    char* in = "hello world";
    unsigned char digest[16] ={0};
    MD5(in, strlen(in), digest);
    for(int i = 0; i < 16; i++)
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
    X509_ALGOR* alg;
    X509_SIG* sig = X509_SIG_new();
    ASN1_OCTET_STRING* dgst;
    X509_SIG_getm(sig, &alg, &dgst);
    alg->algorithm=OBJ_nid2obj(NID_md5);
    ASN1_OCTET_STRING_set(dgst, digest, 16);
    


    //========================================================
    BIO* fbio = BIO_new_file("x509_sig.der", "w");
    int len=i2d_X509_SIG(sig,NULL);
    p=buf= (unsigned char*)OPENSSL_malloc(len);
    len=i2d_X509_SIG(sig,&p);
    BIO_write(fbio, buf, len);
    BIO_flush(fbio);
    BIO_free(fbio);
    X509_SIG_free(sig);
    OPENSSL_free(buf);
    //========================================================
    p=buf= (unsigned char*)OPENSSL_malloc(len);
    fbio = BIO_new_file("x509_sig.der", "r");
    BIO_read(fbio, buf, len);

    X509_SIG* sig_dup = X509_SIG_new();
    d2i_X509_SIG(&sig_dup, &buf, len);
    X509_ALGOR* alg_dup;
    ASN1_OCTET_STRING* dgst_dup;
    X509_SIG_get0(sig, &alg_dup, &dgst_dup);
    if(OBJ_obj2nid(alg_dup->algorithm) == NID_md5)
    {
        printf("algorithm:NID_md5\n");
        unsigned char* str = dgst_dup->data;
        for(int i = 0; i < dgst_dup->length; i++)
        {
            printf("%02x", str[i]);
        }
        printf("\n");
    }
    BIO_free(fbio);
    X509_SIG_free(sig_dup);
    
    
}

void x509_name()
{
    printf("===================================%s====================================\n",__func__);
    X509_NAME* name = X509_NAME_new();

    //"C=UK, O=Disorganized Organization, CN=Joe Bloggs L=Local"
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "UK", -1, -1, 0);

    ASN1_OBJECT* obj = OBJ_nid2obj(NID_organizationName);
    X509_NAME_add_entry_by_OBJ(name, obj, V_ASN1_UTF8STRING, "Disorganized Organization", -1,-1, 0);

    X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_UTF8STRING, "Joe Bloggs", -1 ,-1,0);

    X509_NAME_ENTRY* ne = X509_NAME_ENTRY_new();
    ASN1_OBJECT* localityname_obj = OBJ_nid2obj(NID_localityName);
    X509_NAME_ENTRY_set_object(ne, localityname_obj);
    X509_NAME_ENTRY_set_data(ne, V_ASN1_UTF8STRING, "Local", -1);
    X509_NAME_add_entry(name, ne, -1, 0);

    // X509_NAME_ENTRY_create_by_OBJ
    // X509_NAME_ENTRY_create_by_txt
    X509_NAME_ENTRY * ou = X509_NAME_ENTRY_create_by_txt(NULL, "OU", V_ASN1_UTF8STRING, "Organizational Unit Name", -1);
    X509_NAME_add_entry(name, ou, -1, 0);

    char name_buf[1024] = {0};
    X509_NAME_oneline(name, name_buf, 1024);
    printf("name:%s\n", name_buf);

    printf("name entry count:%d\n", X509_NAME_entry_count(name));
    unsigned char md[16];
    unsigned int mdlen = 16;
    X509_NAME_digest(name, EVP_md5(),md, &mdlen);
    printf("name digest:");
    for(int i = 0; i < mdlen; i++)
    {
        printf("%02x", md[i]);
    }
    printf("\n");
    unsigned long h = X509_NAME_hash(name);
    printf("name hash:%ld\n", h);

    int index = X509_NAME_get_index_by_NID(name, NID_countryName, -1);
    printf("Country Name index:%d\n", index);

    X509_NAME_delete_entry(name, index);

    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_NAME_print(out, name, 0);

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, out);
    int len = i2d_X509_NAME(name,NULL);
    unsigned char* der = (unsigned char*) OPENSSL_malloc(len);
    unsigned char* p = der;
    i2d_X509_NAME(name,&p);
    BIO_write(b64, der, len);
    BIO_flush(b64);

    BIO_free_all(b64);
    X509_NAME_ENTRY_free(ou);
    X509_NAME_ENTRY_free(ne);
    X509_NAME_free(name);
}

void x509_ext()
{
    printf("===================================%s====================================\n",__func__);
    X509_EXTENSION *ext=NULL;
    ASN1_OBJECT *obj = NULL;
    char buf[100];
    int buflen=100;
    time_t t;
    PKEY_USAGE_PERIOD *period = PKEY_USAGE_PERIOD_new();
    //t = time(0);
    period->notBefore=ASN1_GENERALIZEDTIME_set(period->notBefore,t);
    t=100;
    period->notAfter=ASN1_GENERALIZEDTIME_set(period->notAfter,t);
    int len=i2d_PKEY_USAGE_PERIOD(period,NULL);
    unsigned char* der=(unsigned char *)OPENSSL_malloc(len);
    unsigned char* p = der;
    len=i2d_PKEY_USAGE_PERIOD(period,&p);

    ASN1_OCTET_STRING* data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(data,der,len);

#if 1
    X509_EXTENSION_create_by_NID(&ext,NID_private_key_usage_period,1,data);
#else
    obj=OBJ_nid2obj(NID_private_key_usage_period);
    X509_EXTENSION_create_by_OBJ(&ext,obj,1,data);
#endif
    obj=X509_EXTENSION_get_object(ext);
    OBJ_obj2txt(buf,buflen,obj,0);
    printf("extions obj : %s\n",buf);

    data = X509_EXTENSION_get_data(ext);
    BIO* b = BIO_new_fp(stdout, BIO_NOCLOSE);
    ASN1_STRING_print(b,data);
    BIO_flush(b);
    printf("\n");

    X509_EXTENSION_set_critical(ext,0);
    int ret = X509_EXTENSION_get_critical(ext);
    if(ret == 1)
    {
        printf("critical\n");
    }
    else
    {
        printf("not critical\n");
    }
    

    PKEY_USAGE_PERIOD_free(period);
    ASN1_OCTET_STRING_free(data);
    OPENSSL_free(der);
    BIO_free(b);
}

void x509_v3_ext()
{
    printf("===================================%s====================================\n",__func__);
    X509_EXTENSION *ext = NULL;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    PKEY_USAGE_PERIOD *period;
    time_t t;

    period=PKEY_USAGE_PERIOD_new();
    t=1;
    period->notBefore=ASN1_GENERALIZEDTIME_set(period->notBefore,t);
    t=100;
    period->notAfter=ASN1_GENERALIZEDTIME_set(period->notAfter,t);

    /* 根据具体的扩展项构造一个 X509_EXTENSION */
    char buf[100];
    int buflen=100;
    ext=X509V3_EXT_i2d(NID_private_key_usage_period, 1, period);
    ASN1_OBJECT *obj=X509_EXTENSION_get_object(ext);
    OBJ_obj2txt(buf,buflen,obj,0);
    printf("extions obj : %s\n",buf);


    /* 根据具体的扩展项构造一个 X509_EXTENSION 堆栈*/
    int ret=X509V3_add1_i2d(&exts, NID_private_key_usage_period, period, 1, X509V3_ADD_DEFAULT);
    X509_EXTENSION_free(ext);
    sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);

}

void x509_attr()
{
    printf("===================================%s====================================\n",__func__);
    ASN1_STRING *str = ASN1_STRING_new();
    ASN1_STRING_set(str, "a@a.com",7);
    str->length = 7;
    //X509_ATTRIBUTE_create_by_OBJ
    //X509_ATTRIBUTE_create_by_NID
    //X509_ATTRIBUTE_create_by_txt
    X509_ATTRIBUTE * attr = X509_ATTRIBUTE_create(NID_SMIMECapabilities,V_ASN1_UTF8STRING, str);
    printf("attr count:%d\n", X509_ATTRIBUTE_count(attr));

}

//typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES；
void x509_general_name()
{
    printf("===================================%s====================================\n",__func__);
    GENERAL_NAMES *gns;
    GENERAL_NAME *gn;

    gns=sk_GENERAL_NAME_new_null();

    gn=GENERAL_NAME_new();
    /* 设置 gn 的值为一个 rfc822Name */
    gn->type=GEN_EMAIL;
    gn->d.rfc822Name=ASN1_STRING_new();
    ASN1_STRING_set(gn->d.rfc822Name,"a@a.com",7);
    sk_GENERAL_NAME_push(gns,gn);

    gn=GENERAL_NAME_new();
    /* 设置 gn 的值为一个 GEN_DIRNAME */
    gn->type=GEN_DIRNAME;
    gn->d.directoryName=X509_NAME_new();
    X509_NAME_add_entry_by_txt(gn->d.directoryName,LN_commonName,V_ASN1_UTF8STRING,"aaaaa",5,0,-1);
    sk_GENERAL_NAME_push(gns,gn);

    int len = i2d_GENERAL_NAMES(gns,NULL);
    unsigned char* buf=(unsigned char*)OPENSSL_malloc(len);
    unsigned char* p = buf;
    len=i2d_GENERAL_NAMES(gns,&p);
    
    
    BIO* out = BIO_new_fp(stdout , BIO_NOCLOSE);
    gn = sk_GENERAL_NAME_value(gns, 0);
    GENERAL_NAME_print(out, gn);
    printf("\n");
    gn = sk_GENERAL_NAME_value(gns, 1);
    GENERAL_NAME_print(out, gn);
    printf("\n");
    BIO_free(out);

    sk_GENERAL_NAME_pop_free(gns,GENERAL_NAME_free);

}

void x509_store()
{
    printf("===================================%s====================================\n",__func__);
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

    // ext
    STACK_OF(X509_EXTENSION) *exts = NULL;
    PKEY_USAGE_PERIOD *period;
    time_t t;
    period=PKEY_USAGE_PERIOD_new();
    t=1;
    period->notBefore=ASN1_GENERALIZEDTIME_set(period->notBefore,t);
    t=100;
    period->notAfter=ASN1_GENERALIZEDTIME_set(period->notAfter,t);
    X509V3_add1_i2d(&exts, NID_private_key_usage_period, period, 1, X509V3_ADD_DEFAULT);

    int len = sk_X509_EXTENSION_num(exts);
    for(int i = 0; i < len; i++)
    {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        X509_add_ext(x, ext, -1);
    }

    // signature
    X509_sign(x, pkey, EVP_md5());

    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_print(out, x);
    BIO_free(out);

    BIO* file = BIO_new_file("x509.pem", "w");
    PEM_write_bio_X509(file, x);
    BIO_free(file);

    sk_X509_EXTENSION_pop_free(exts,X509_EXTENSION_free);
    EVP_PKEY_free(pkey);
    X509_NAME_free(name);
    ASN1_INTEGER_free(sn);
    X509_free(x);
}

void x509_load()
{
    printf("===================================%s====================================\n",__func__);
    X509 *x;
    
    BIO* file = BIO_new_file("x509.pem", "r");
    x = PEM_read_bio_X509(file, NULL, NULL, NULL);
    BIO_free(file);

    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_print(out, x);
    BIO_free(out);

    
    int ret =  X509_check_purpose(x, X509_PURPOSE_OCSP_HELPER, 1);
    if (ret == 1)
    {
        printf("X509_PURPOSE_OCSP_HELPER purpose check ok!\n");
    }
    else
    {
        printf("X509_PURPOSE_OCSP_HELPER purpose check failed!\n");
    }
}

int main(int argc, char const *argv[])
{
#if 0
    x509_alg();
    int len = store_SEQ_X509();
    printf("len:%d\n", len);
    load_SEQ_X509(len);
    x509_alg();
    x509_val();
    x509_sig();
    x509_name();
    x509_ext();
    x509_v3_ext();
    x509_attr();
    x509_general_name();
#endif
    x509_store();
    x509_load();
    return 0;
}
