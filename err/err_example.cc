#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/bn.h>

//各模块实现的，加载各自错误信息
/*
ERR_load_ASN1_strings
ERR_load_BIO_strings
ERR_load_BN_strings
ERR_load_BUF_strings
ERR_load_COMP_strings
ERR_load_CONF_strings
ERR_load_CRYPTO_strings
ERR_load_crypto_strings
ERR_load_DH_strings
ERR_load_DSA_strings
ERR_load_DSO_strings
ERR_load_EC_strings
ERR_load_ENGINE_strings
ERR_load_ERR_strings
ERR_load_EVP_strings
ERR_load_OBJ_strings
ERR_load_OCSP_strings
ERR_load_PEM_strings
ERR_load_PKCS12_strings
ERR_load_PKCS7_strings
ERR_load_RAND_strings
ERR_load_RSA_strings
ERR_load_UI_strings
ERR_load_X509_strings
ERR_load_X509V3_strings
*/


int mycb(const char *str,size_t b,void *c)
{
    printf("my print :str: %s", str);
    printf("size: %ld \n",b);
    printf("other:%s\n", c);
    return 0;
}

void err_log()
{
    printf("=====================%s====================\n", __func__);

    unsigned long err;
    const char *data;
    const char *efunc;
    const char *elib;
    const char *ereason;
    char estring[500] = {0};
    const char *p;
    int flags;
    const char *file;

    int line;
    BIO *berr = BIO_new_fp(stdout, BIO_NOCLOSE);

    ERR_load_BIO_strings();
    ERR_clear_error();

    BIO_new_file("no.exist", "r");

#if 1
    err = ERR_peek_last_error();
    printf("lib code %d func code:%d resone code:%d\n", ERR_GET_LIB(err), ERR_GET_FUNC(err), ERR_GET_REASON(err));

    if (ERR_PACK(ERR_LIB_BIO, 109, 128) == err)
    {
        printf("error code:%d\n", err);
    }

    err = ERR_peek_last_error_line(&file, &line);
    printf("ERR_peek_last_error_line err : %ld,file : %s,line: %d\n", err, file, line);
#endif

    err = ERR_peek_last_error_line_data(&file, &line, &data, &flags);
    printf("ERR_peek_last_error_line_data err: %ld, file :%s, line :%d, data :%s flags:%d\n", err, file, line, data, flags);

    err = ERR_peek_error();
    printf("ERR_peek_error err: %ld\n", err);

    err = ERR_peek_error_line(&file, &line);
    printf("ERR_peek_error_line err : %ld,file : %s, line: %d\n", err, file, line);

    err = ERR_peek_error_line_data(&file, &line, &data, &flags);
    printf("ERR_peek_error_line_data err : %ld, file :%s, line :%d, data :%s, flags:%d\n", err, file, line, data, flags);

    err = ERR_get_error_line_data(&file, &line, &data, &flags);
    printf("ERR_get_error_line_data err : %ld,file :%s,line :%d,data :%s, flags:%d\n", err, file, line, data, flags);

    printf("-----------------------------------------------------\n");
    err = ERR_get_error();
    if (err != 0)
    {
        printf("ERR_get_error err : %ld\n", err);
        elib = ERR_lib_error_string(err);
        printf("ERR_lib_error_string : %s\n", elib);

        efunc = ERR_func_error_string(err);
        printf("ERR_func_error_string : %s\n", efunc);

        ereason = ERR_reason_error_string(err);
        printf("ERR_reason_error_string : %s\n", ereason);

        ERR_error_string(err, estring);
        printf("ERR_error_string : %s\n", estring);

        ERR_error_string_n(err, estring, sizeof(estring));
        printf("ERR_error_string_n : %s\n", estring);
    }

    //========================================================
    printf("-----------------------------------------------------\n");
    printf("write errors to file err.log\n");
    BIO_new_file("no.exist2","r");
    FILE* fp = fopen("err.log", "w");
    ERR_print_errors_fp(fp);
    fclose(fp);


    //========================================================
    BIO_new_file("no.exist3", "r");
    ERR_print_errors(berr);
    printf("-----------------------------------------------------\n");

    //==========================================================
    BIO_new_file("no.exist4","r");
    ERR_print_errors_cb(mycb,(void*)"this a custom");
    ERR_print_errors(berr);
    printf("-----------------------------------------------------\n");

    //===========================================================
    ERR_put_error(ERR_LIB_BIO,BIO_F_BIO_ACCEPT,BIO_R_ACCEPT_ERROR,__FILE__,__LINE__);
    ERR_print_errors(berr);
    printf("-----------------------------------------------------\n");
    //===========================================================

    ERR_put_error(ERR_LIB_BIO,BIO_F_BIO_BIND,BIO_R_IN_USE,__FILE__,__LINE__);
    ERR_set_error_data("set date test!\n", ERR_TXT_STRING);
    err = ERR_set_mark();
    ERR_print_errors(berr);

    //===========================================================
    ERR_free_strings();
    BIO_free(berr);
}

int main(int argc, char const *argv[])
{
    err_log();
    return 0;
}
