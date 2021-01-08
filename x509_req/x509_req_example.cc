#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void x509_req_store()
{
    X509_REQ *req;
    X509_NAME* subject;
    X509_NAME_ENTRY *entry=NULL;
    EVP_PKEY *pkey;
    RSA *rsa;
    const EVP_MD *md;
    unsigned char mdout[20] = {0};
    unsigned int mdlen;
    printf("==============================%s==============================\n",__func__);
    
    req = X509_REQ_new();

    /*version*/
    X509_REQ_set_version(req, 1);

    /*subject*/
    subject = X509_NAME_new();
    entry = X509_NAME_ENTRY_create_by_txt(&entry, "commonName", V_ASN1_UTF8STRING, "openssl", -1);
    X509_NAME_add_entry(subject, entry, 0, -1);
    entry=X509_NAME_ENTRY_create_by_txt(&entry,"countryName", V_ASN1_UTF8STRING, "bj", -1);
    X509_NAME_add_entry(subject, entry, 0, -1);
    X509_REQ_set_subject_name(req, subject);

    /* pub key */
    pkey=EVP_PKEY_new();
    rsa=RSA_generate_key(1024, RSA_3, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_REQ_set_pubkey(req, pkey);

    /* attribute */
    X509_REQ_add1_attr_by_txt(req, "organizationName", V_ASN1_UTF8STRING, "test", strlen("test"));
    X509_REQ_add1_attr_by_txt(req,"organizationalUnitName",V_ASN1_UTF8STRING, "ttt", strlen("ttt"));

    md = EVP_sha1();
    X509_REQ_digest(req, md, mdout, &mdlen);
    printf("x509 req digest:");
    for(int i =0 ; i < mdlen; i++)
    {
        printf("%02x", mdout[i]);
    }
    printf("\n");

    //signature
    X509_REQ_sign(req, pkey, md);

    BIO* pemfile = BIO_new_file("x509_req.pem", "w");
    PEM_write_bio_X509_REQ(pemfile, req);
    BIO_free(pemfile);

    //================================
    EVP_PKEY_free(pkey);
    X509_NAME_free(subject);
    X509_REQ_free(req);

}

void x509_req_load()
{
    X509_REQ *req;
    BIO *pemfile;
    X509_NAME* subject;
    X509_NAME_ENTRY *entry=NULL;
    EVP_PKEY *pkey;
    RSA *rsa;
    const EVP_MD *md;
    unsigned char mdout[20] = {0};
    unsigned int mdlen;

    printf("==============================%s==============================\n",__func__);
    //req = X509_REQ_new();

    pemfile = BIO_new_file("x509_req.pem", "r");
    req = PEM_read_bio_X509_REQ(pemfile, NULL, NULL, NULL);
    BIO_free(pemfile);

    md = EVP_sha1();
    X509_REQ_digest(req, md, mdout, &mdlen);
    printf("x509 req digest:");
    for(int i =0 ; i < mdlen; i++)
    {
        printf("%02x", mdout[i]);
    }
    printf("\n");
    printf("x509_req:\n");

    /*version*/
    long version = X509_REQ_get_version(req);
    printf("\tversion:\t%d\n",version);

    /*subject*/
    subject = X509_REQ_get_subject_name(req);
    int subject_count = X509_NAME_entry_count(subject);
    printf("\tsubject:\n");
    for(int i = 0; i < subject_count; i++)
    {
        entry = X509_NAME_get_entry(subject, i);
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        char buf[20] = {0};
        OBJ_obj2txt(buf, 20, obj, 0);
        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        printf("\t\t%s:%s\n", buf, data->data);

    }

    /* pub key */
    pkey = X509_REQ_get_pubkey(req);
    rsa = EVP_PKEY_get0_RSA(pkey);
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    printf("\tpkey:\n");
    RSA_print(out, rsa, 15);
    BIO_free(out);

    /* attribute*/
    int attr_count = X509_REQ_get_attr_count(req);
    printf("\tattribute:\n");
    for(int i = 0; i < attr_count; i++)
    {
        X509_ATTRIBUTE* attr = X509_REQ_get_attr(req, i);
        
        ASN1_OBJECT* obj = X509_ATTRIBUTE_get0_object(attr);
        char buf[40] = {0};
        OBJ_obj2txt(buf, 40, obj, 0);

        ASN1_TYPE* t = X509_ATTRIBUTE_get0_type(attr, 0);

        ASN1_STRING* attr_data;
        attr_data =(ASN1_STRING*) X509_ATTRIBUTE_get0_data(attr, 0, t->type, NULL);
        printf("\t\t%s:%d:%s\n", buf, t->type, attr_data->data);
    }

    /* verify */
    int ret = X509_REQ_verify(req, pkey);
    if(ret == 1)
    {
        printf("x509 req verify success\n");
    }
    else
    {
        printf("x509 req verify fail\n");
    }
    
    //======================================
    //X509_REQ_free(req);
}

int main(int argc, char const *argv[])
{
    x509_req_store();
    x509_req_load();
    return 0;
}
