#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int mycb(char* passwd, int num, int a, char* key)
{
    if(key)
    {
        strcpy(passwd, key);
    }
    else
    {
        if(a == 1)
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

void handle_pem()
{
    int ret;
    BIO* rsa_pub;
    BIO* rsa_priv;
    RSA* r = RSA_new();
    BIGNUM* bne = BN_new();
    ret = BN_set_word(bne, RSA_3);
    char err_string[1024] = {0};

    ERR_load_PEM_strings();
    OpenSSL_add_all_algorithms();
    
    const EVP_CIPHER* enc = EVP_des_cbc();

    ret = RSA_generate_key_ex(r,1024, bne, NULL);
    if(ret != 1)
    {
        ERR_error_string(ERR_get_error(), err_string);
        printf("rsa gen key fail: %s\n", err_string);
        goto end;
    }

    

    rsa_pub = BIO_new_file("rsa_pub.pem", "w");
    PEM_write_bio_RSAPublicKey(rsa_pub, r);
    BIO_flush(rsa_pub);

    rsa_priv = BIO_new_file("rsa_pri.pem", "w");
    //PEM_write_bio_RSAPrivateKey(rsa_priv, r, enc, NULL, 0, mycb, NULL);
    //PEM_write_bio_RSAPrivateKey(rsa_priv, r, enc, NULL, 0, mycb, "123456");
    ret = PEM_write_bio_RSAPrivateKey(rsa_priv, r, enc, "123456", 6, NULL, NULL);
    if(ret != 1)
    {
        ERR_error_string(ERR_get_error(), err_string);
        printf("write pri key fail: %s\n", err_string);
    }
    BIO_flush(rsa_priv);
//=========================================================================
    char *name=NULL;
    char *header=NULL;
    char *pub_data=NULL;
    long pub_data_len = 0;
    char *pri_data=NULL;
    long pri_data_len = 0;
    BIO* rsa_r_priv = BIO_new_file("rsa_pri.pem", "r");
    BIO* rsa_r_pub = BIO_new_file("rsa_pub.pem", "r");

    //  name --- RSA PRIVATE KEY, CERTIFICATE,etc.
    ret = PEM_bytes_read_bio(&pub_data, &pub_data_len, &name, "RSA PUBLIC KEY", rsa_r_pub, NULL, NULL);
    if(ret != 1)
    {
        ERR_error_string(ERR_get_error(), err_string);
        printf("read pub key fail: %s\n", err_string);        
    }

    printf("name :%s\n", name);

    RSA* r_pub = d2i_RSAPublicKey(NULL, &pub_data, pub_data_len);
    if(r_pub == NULL)
    {
        ERR_error_string(ERR_get_error(), err_string);
        printf("d2i pub key fail: %s\n", err_string);   
    }
    else
    {
        printf("get rsa pub key success\n");
        BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
        RSA_print(out, r_pub, 0);
        BIO_free(out);
    }




    //=========================================================
    printf("------------------------------------------------------------------------------\n");
    EVP_CIPHER_INFO cipherinfo;
    while (1)
    {
        ret = PEM_read_bio(rsa_r_priv, &name, &header, &pri_data, &pri_data_len);
        if (ret == 0)
        {
            break;
        }
        printf("name :%s\n", name);
        if (strlen(header) > 0)
        {
            ret = PEM_get_EVP_CIPHER_INFO(header, &cipherinfo);
            ret = PEM_do_header(&cipherinfo, pri_data, &pri_data_len, mycb, "123456");
            if (ret == 0)
            {
                printf("PEM_do_header err!\n");
                return;
            }
            else
            {
                printf("get rsa pri key success\n");
            }
            RSA* r_pri = d2i_RSAPrivateKey(NULL, &pri_data, pri_data_len);
            BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
            RSA_print(out, r_pri, 0);
            BIO_free(out);
        }
    }

    //=======================================================


    BIO_free(rsa_r_priv);
    BIO_free(rsa_r_pub);

end:
    BN_free(bne);
    RSA_free(r);
    BIO_free(rsa_pub);
    BIO_free(rsa_priv);
}

int main(int argc, char const *argv[])
{
    handle_pem();
    return 0;
}
