#include <string.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>


void* custom_malloc(size_t num, const char * file, int line)
{
    printf("%s: malloc %d in %s:%d\n", __func__, num, file, line);
    return NULL;
}

void* custom_remalloc(void * ptr, size_t num, const char *file, int line)
{
    printf("%s: remalloc %p:%d in %s:%d\n", __func__, ptr,num, file, line);
    return NULL;
}

void custom_free(void * ptr, const char *file, int line)
{
    printf("%s: free %p in %s:%d\n", __func__, ptr, file, line);
    return;
}

typedef  void *(*malloc_func)(size_t, const char *, int);
typedef  void *(*remalloc_func)(void *, size_t, const char *, int);
typedef  void (*free_func)(void *, const char *, int);

void crypto_set_func()
{
    malloc_func m;
    remalloc_func r;
    free_func f;
    //void *(*m)(size_t, const char *, int);
    //void *(*r)(void *, size_t, const char *, int);
    //void (*f)(void *, const char *, int);
    CRYPTO_get_mem_functions(&m, &r, &f);

    CRYPTO_set_mem_functions(custom_malloc, custom_remalloc, custom_free);
    char* cm = (char*)OPENSSL_malloc(10);
    cm = (char*)OPENSSL_realloc(cm, 10);
    OPENSSL_free(cm);
    CRYPTO_set_mem_functions(m, r, f);
}

void openssl_memory_test()
{
    char* pm = (char*)OPENSSL_malloc(16);
    pm[0] = 'c';
    char* pz = (char*)OPENSSL_zalloc(16);
    OPENSSL_strlcpy(pz, "aaaaaaa", 7);
    printf("pz:%s\n", pz);


    char* pdup = OPENSSL_strdup("bbbbbb");
    printf("pdup:%s\n", pdup);

    OPENSSL_strlcat(pz, pdup, 7);
    printf("pz:%s\n", pz);

    char* pmdup = (char*)OPENSSL_memdup(pm, 16);
    printf("pmdup:%s\n", pmdup);

    char* preloc = (char*)OPENSSL_realloc(pmdup, 32);
    printf("preloc:%s\n", preloc);

    OPENSSL_free(pm);
    OPENSSL_clear_free(pz, 16);
    OPENSSL_free(pdup);
    OPENSSL_free(preloc);

    long len = 9;

    char* phexstr2buf = (char*)OPENSSL_hexstr2buf("31323334FFF0", &len);  // "31"--> 49
    printf(" len: %ld\n", len);
    for(int i = 0; i < len; i++)
    {
        printf("%d ", phexstr2buf[i]);
    }
    OPENSSL_free(phexstr2buf);
    printf("\n");

    const unsigned char buffer[] = {49, 50,51,52, 254};
    char*pbuf2hexstr =(char*)OPENSSL_buf2hexstr(buffer, 4); // 49->"31"
    printf("pbuf2hexstr:%s\n", pbuf2hexstr);
    OPENSSL_free(pbuf2hexstr);

    char c = 'f';
    printf("hexchar2int:%d\n", OPENSSL_hexchar2int(c));

}


int main(int argc, char *argv[])
{
    crypto_set_func();
    openssl_memory_test();
    return 0;
}
