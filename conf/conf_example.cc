#include <openssl/conf.h>



void printfConfValue(CONF_METHOD* meth)
{
    CONF* conf;
    long eline = 0;  //出错行
    long result;
    int ret;
    char* p;
    BIO* bp;
    char* defaultConfFile;
    STACK_OF(CONF_VALUE) *v;
    int itemNum;
    CONF_VALUE* item;

    defaultConfFile = CONF_get1_default_config_file();
    printf("defult config file:%s\n", defaultConfFile);

    conf = NCONF_new(meth);
#if 0
    bp = BIO_new_file(defaultConfFile, "r");
    NCONF_load_bio(conf, bp, &eline);
#else
    ret = NCONF_load(conf, defaultConfFile, &eline);
    if(ret != 1)
    {
        printf("load config fail!\n");
        return;
    }
#endif
    printf("eline:%ld\n", eline);

    p = NCONF_get_string(conf, NULL, "RANDFILE");
    if(p == NULL)
    {
        printf("no global RANDFILE info\n");
    }
    else
    {
        printf("RANDFILE = %s\n", p);
    }
    
    p = NCONF_get_string(conf, "CA_default", "default_days");
    printf("[ CA_default ] default_days = %s\n", p);

    ret=NCONF_get_number_e(conf,"CA_default","default_days",&result);
    printf("[ CA_default ] default_days = %ld\n", result);

    ret=NCONF_get_number(conf,"CA_default","default_days",&result);
    printf("[ CA_default ] default_days = %ld\n", result);

    v = NCONF_get_section(conf,"CA_default");
    itemNum = sk_CONF_VALUE_num(v);
    printf("CA_default item number:%d\n", itemNum);

    for(int i = 0; i < itemNum; i++)
    {
        item = sk_CONF_VALUE_value(v, i);
        printf("[ %s ] %s = %s\n", item->section, item->name, item->value);
    }

    NCONF_free(conf);
}

//=================================================================

extern CONF_METHOD custom_method;

CONF *customCreate(CONF_METHOD *meth)
{
    printf("%s\n", __func__);
    CONF *ret;

    ret = (CONF *)OPENSSL_malloc(sizeof(*ret));
    if (ret != NULL)
        if (meth->init(ret) == 0)
        {
            OPENSSL_free(ret);
            ret = NULL;
        }
    return ret;
}

int main(int argc, char const *argv[])
{
    printfConfValue(NULL);
    printf("======================================================\n");
    CONF_METHOD* custom_method = NCONF_default();
    custom_method->create = customCreate;  // replace creat function
    printfConfValue(custom_method);
    return 0;
}
