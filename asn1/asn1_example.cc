#include <stdlib.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>


/*
asn1 = SEQUENCE:seq_section

[seq_section]
field1 = BOOLEAN:TRUE
field2 = INTEGER:0x01
field3 = SEQUENCE:seq_child
 
[seq_child]
field1 = INTEGER:0x02
field2 = INTEGER:0x03
*/

 typedef struct SeqChild_st
 {
    ASN1_INTEGER*   value1;
    ASN1_INTEGER*   value2;
 } SEQ_CHILD;
 DECLARE_ASN1_FUNCTIONS(SEQ_CHILD);

ASN1_SEQUENCE(SEQ_CHILD) = 
{
    ASN1_SIMPLE(SEQ_CHILD, value1, ASN1_INTEGER),
    ASN1_SIMPLE(SEQ_CHILD, value2, ASN1_INTEGER)
}
ASN1_SEQUENCE_END(SEQ_CHILD)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_CHILD)

typedef struct SeqSection_st
{
   ASN1_BOOLEAN            flag;
   ASN1_INTEGER*           value;
   SEQ_CHILD*              child_seq;
} SEQ_SECTION;
DECLARE_ASN1_FUNCTIONS(SEQ_SECTION);
ASN1_SEQUENCE(SEQ_SECTION) =
{
    ASN1_SIMPLE(SEQ_SECTION, flag, ASN1_BOOLEAN),
    ASN1_SIMPLE(SEQ_SECTION, value, ASN1_INTEGER),
    ASN1_SIMPLE(SEQ_SECTION, child_seq, SEQ_CHILD)
}
ASN1_SEQUENCE_END(SEQ_SECTION)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_SECTION)


void asn1_der_codec()
{
    unsigned char derEcode[1024] = {0};
    int ret;
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO* outFile = BIO_new_file("section.cer", "w");
    BIO* inFile = BIO_new_file("section.cer", "r");
    BIO* base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, out);
    printf("==============================%s==================================\n",__func__);
    SEQ_SECTION* section = SEQ_SECTION_new();

    // construct
    section->flag = 0x01;
    section->value = ASN1_INTEGER_new();
    ASN1_INTEGER_set(section->value, 0x01);
    section->child_seq = SEQ_CHILD_new();

    section->child_seq->value1 = ASN1_INTEGER_new();
    section->child_seq->value2 = ASN1_INTEGER_new();

    ASN1_INTEGER_set(section->child_seq->value1, 0x02);
    ASN1_INTEGER_set(section->child_seq->value2, 0x03);
    //=================================================================

    // encode
    ret = i2d_SEQ_SECTION(section, (unsigned char**)&derEcode);
    printf("ret:%d\n",ret);
    
    printf("i2d: ");
    for(int i = 0; i < ret; i++)
    {
        printf("%02x ", derEcode[i]);
    }
    printf("\n");

    printf("-------------------------------------------------------------------------\n");
    printf("i2d base64: ");
    ASN1_i2d_bio(i2d_SEQ_SECTION, base64Bio, derEcode);
    BIO_flush(base64Bio);
    //==================================================================

    // decode
    SEQ_SECTION* decSection = SEQ_SECTION_new();
    d2i_SEQ_SECTION(&decSection, (unsigned char**)&derEcode, ret);

    printf("seq section:\n");
    printf("\tflag:%d\n", decSection->flag);
    printf("\tvalude:%d\n", ASN1_INTEGER_get(decSection->value));
    printf("\tseq child:\n");
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decSection->child_seq->value1));
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decSection->child_seq->value2));
    //====================================================================================
    

    //===================================================================================
    

    // =====================save to file==========================
    ASN1_i2d_bio(i2d_SEQ_SECTION, outFile, (unsigned char*)section);
    BIO_flush(outFile);


    //===================================================================
    SEQ_SECTION** decBioOutSection;
    decBioOutSection=(SEQ_SECTION **)OPENSSL_malloc(sizeof(SEQ_SECTION **));
    SEQ_SECTION* decBioSection = (SEQ_SECTION*)ASN1_d2i_bio(NULL, d2i_SEQ_SECTION, inFile, decBioOutSection);
    printf("seq section:\n");
    printf("\tflag:%d\n", decBioSection->flag);
    printf("\tvalude:%d\n", ASN1_INTEGER_get(decBioSection->value));
    printf("\tseq child:\n");
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decBioSection->child_seq->value1));
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decBioSection->child_seq->value2));

    //======================================================================================


    SEQ_SECTION_free(decBioSection);
    SEQ_SECTION_free(decSection);
    SEQ_SECTION_free(section);
    BIO_free_all(base64Bio);
    BIO_free(outFile);
    BIO_free(inFile);
    OPENSSL_free(decBioOutSection);
}



void asn1_object_create()
{
    const char* oid = "2.99999.2";  // object id
    ASN1_OBJECT* obj;
    int der_len;
    unsigned char der[1024] = {0};
    printf("==============================%s=============================\n",__func__);
    //======================================================================================
    int new_nid = OBJ_create(oid,"testSN", "testLN");
    obj = OBJ_nid2obj(new_nid);

    der_len = i2d_ASN1_OBJECT(obj, (unsigned char**)&der);

    printf("i2d buf: ");
    for(int i = 0; i < der_len; i++)
    {
        printf("%02x ", der[i]);
    }
    printf("\n");

    ASN1_OBJECT* new_obj = d2i_ASN1_OBJECT(NULL, (unsigned char**)&der, der_len);
    if(new_obj != NULL)
    {
        printf("i2d: ");
        BIO* outFile = BIO_new(BIO_s_mem());
        ASN1_i2d_bio(i2d_ASN1_OBJECT, outFile, (unsigned char*)new_obj);
        unsigned char data[10] = {0};
        int len = BIO_read(outFile, data, 10);
        for(int i = 0; i < len; i++)
        {
            printf("%02x ", data[i]);
        }
        printf("\n");
        BIO_free(outFile);
    }
    //======================================================================================

    ASN1_OBJECT_free(new_obj);
    OBJ_cleanup();

}

void asn1_a2i_INTEGER()
{
    printf("==============================%s=============================\n",__func__);
    ASN1_INTEGER* i;
    char buf[50];
    int size = 50;
    BIO* bp = BIO_new(BIO_s_mem());
    int len = BIO_write(bp,"0FAB08BBDDEECC",14);
    i = ASN1_INTEGER_new();
    a2i_ASN1_INTEGER(bp,i,buf,size);
    printf("0x%s=%ld\n", buf, ASN1_INTEGER_get(i));
    ASN1_INTEGER_free(i);
    BIO_free(bp);
    //===================================================================
}

void asn1_a2i_STRING()
{
    printf("==============================%s=============================\n",__func__);
    ASN1_STRING* str;
    char buf[50];
    int size = 50;
    BIO* bp = BIO_new(BIO_s_mem());
    int len = BIO_write(bp,"B2E2CAD4",8);
    str = ASN1_STRING_new();
    a2i_ASN1_INTEGER(bp,str,buf,size);
    printf("%s=%s\n", buf, ASN1_STRING_data(str)); // 转换后 str->data 的前四个字节即变成"测试"。
    ASN1_STRING_free(str);
    BIO_free(bp);
    //===================================================================
}


void asn1_bit_string()
{
    printf("==============================%s=============================\n",__func__);
    int ret,i,n;
    ASN1_BIT_STRING *a;
    char data[2] = {0x01, 'a'};
    a=ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(a,data,2);
    for (i = 0; i < 2 * 8; i++)
    {
        ret = ASN1_BIT_STRING_get_bit(a, i);
        printf("%d", ret);
    }
    printf("\n");
    ASN1_BIT_STRING_free(a);
}


void asn1_dup()
{
    printf("==============================%s=============================\n",__func__);
    ASN1_INTEGER* i = ASN1_INTEGER_new();
    ASN1_INTEGER* dup;

    ASN1_INTEGER_set(i, 100);

    dup =(ASN1_INTEGER*)ASN1_dup(i2d_ASN1_INTEGER, d2i_ASN1_INTEGER, i);

    printf("dmp=%d\n",ASN1_INTEGER_get(dup));


    ASN1_INTEGER_free(dup);
    ASN1_INTEGER_free(i);


}

void asn1_ENUMERATED()
{
    printf("==============================%s=============================\n",__func__);
    long ret;
    ASN1_ENUMERATED *a;
    a = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(a, (long)155);
    ret = ASN1_ENUMERATED_get(a);
    printf("%ld\n", ret);
    //===================================================================
}

void asn1_ENUMERATED_to_BN()
{
    printf("==============================%s=============================\n",__func__);
    long ret;
    ASN1_ENUMERATED *a;
    BIGNUM *bn;
    a = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(a, (long)155);
    ret = ASN1_ENUMERATED_get(a);
    bn = BN_new();
    bn = ASN1_ENUMERATED_to_BN(a, bn);
    printf("bn=%s\n", BN_bn2dec(bn));
    BN_free(bn);
    ASN1_ENUMERATED_free(a);
}

void asn1_parse_dump()
{
    printf("==============================%s=============================\n", __func__);
    int ret, len, indent, dump;
    BIO *bp;
    char buf[1000];
    FILE* fp=fopen("section.cer","rb");
    len=fread(buf,1,1000,fp);
    fclose(fp);
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);

    //indent 用来设置打印出来当列之间空格个数， ident 越小，打印内容越
    //紧凑。 dump 表明当 asn1 单元为 BIT STRING 或 OCTET STRING 时，打印内容的字节数

    indent = 0;
    dump = 0;
    ret = ASN1_parse_dump(bp, buf, 5000, indent, dump);
    BIO_free(bp);

}

void asn1_string_dup()
{
    printf("==============================%s=============================\n", __func__);
    ASN1_STRING *a = ASN1_STRING_new();
    ASN1_STRING_set(a,"xxx",3);
    ASN1_STRING *b =ASN1_STRING_dup(a);

    printf("a=%s\n",ASN1_STRING_data(a));
    printf("b=%s\n",ASN1_STRING_data(b));
    int ret=ASN1_STRING_cmp(a,b);
    if(ret == 0)
    {
        printf("a==b\n");
    }
    ASN1_STRING_free(a);
    ASN1_STRING_free(b);
}


void asn1_oid_der()
{
    const char* oid = "2.99999.3";  // object id
    unsigned char* payload;
    ASN1_OBJECT* obj = NULL;
    int payload_len;
    int der_len;
    unsigned char der[1024] = {0};

    printf("==============================%s=============================\n",__func__);
    payload_len = a2d_ASN1_OBJECT(NULL, 0, oid, -1);

    payload = (unsigned char*)OPENSSL_malloc(payload_len* sizeof(unsigned char));

    //OID 的 DER 编码
    payload_len = a2d_ASN1_OBJECT(payload, payload_len, oid, -1);
    printf("oid der: ");
    for(int i = 0; i < payload_len; i++)
    {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

void printStrTab(ASN1_STRING_TABLE *str_tab)
{
    printf("str tab:\n");
    printf("\tflag:%ld\n", str_tab->flags);
    printf("\tmask:%ld\n", str_tab->mask);
    printf("\tmaxsize:%ld\n", str_tab->maxsize);
    printf("\tminsize:%ld\n", str_tab->minsize);
    printf("\tnid:%d\n", str_tab->nid);
}

void asn1_STRING_TABLE()
{
    printf("==============================%s=============================\n",__func__);
    const char* oid1 = "2.99999.4";  // object id
    const char* oid2 = "2.99999.5";  // object id
    int nid1 = OBJ_create(oid1,"testSN1", "testLN1");
    int nid2 = OBJ_create(oid2,"testSN2", "testLN2");
    printf("nid1:%d\n",nid1);
    printf("nid2:%d\n",nid2);
    //ASN1_STRING_TABLE它用于约束ASN1_STRING_set_by_NID 函数生成的 ASN1_STRING 类型
    int ret = ASN1_STRING_TABLE_add(nid1, 7, 100, DIRSTRING_TYPE, 0);
    if(ret == 1)
    {
        printf("ASN1_STRING_TABLE_add nid %d success\n", nid1);
    }

    ret = ASN1_STRING_TABLE_add(nid2, 1, 100, PKCS9STRING_TYPE, 0);
    if(ret == 1)
    {
        printf("ASN1_STRING_TABLE_add nid %d success\n", nid2);
    }

    ASN1_STRING_TABLE *str_tab1 = ASN1_STRING_TABLE_get(nid1);
    ASN1_STRING_TABLE *str_tab2 = ASN1_STRING_TABLE_get(nid2);
    printStrTab(str_tab1);
    printStrTab(str_tab2);
//=========================================================================
    unsigned char out[100] = {0};
    unsigned char in[] = {"abcdefg"};
    int inlen = 7;
    int inform=MBSTRING_UTF8;
    ASN1_STRING_set_default_mask(B_ASN1_BMPSTRING);
    ASN1_STRING *str = ASN1_STRING_set_by_NID(NULL, in, inlen, inform, nid1);

    int len =i2d_ASN1_BMPSTRING(str,(unsigned char**)&out);

    switch (str->type)
    {
    case V_ASN1_T61STRING:
        printf("V_ASN1_T61STRING\n");
        break;
    case V_ASN1_IA5STRING:
        printf("V_ASN1_IA5STRING\n");
        break;
    case V_ASN1_PRINTABLESTRING:
        printf("V_ASN1_PRINTABLESTRING\n");
        break;
    case V_ASN1_BMPSTRING:
        printf("V_ASN1_BMPSTRING\n");
        break;
    case V_ASN1_UNIVERSALSTRING:
        printf("V_ASN1_UNIVERSALSTRING\n");
        break;
    case V_ASN1_UTF8STRING:
        printf("V_ASN1_UTF8STRING\n");
        break;
    default:
        printf("err");
        break;
    }

    printf("i2d str:");
    for(int i = 0; i < len; i++)
    {
        printf("%02x ", out[i]);
    }
    printf("\n");

    ASN1_STRING_TABLE_cleanup();
}

void asn1_obj_util()
{
    printf("==============================%s=============================\n",__func__);
    const char* oid = "2.99999.6";
    int nid = -1; 
    nid = OBJ_create(oid, "short name", "long name");
    printf("nid:\t%d\n", nid);
    
    const char * sn = OBJ_nid2sn(nid);
    printf("short name:\t%s\n",sn);

    const char * ln = OBJ_nid2ln(nid);
    printf("long name:\t%s\n",ln);

    nid = -1;
    nid = OBJ_sn2nid(sn);
    printf("sn2nid:%d\n", nid);

    nid = -1;
    nid = OBJ_ln2nid(ln);
    printf("ln2nid:%d\n", nid);

    //============================================================
    printf("---------------------------------------------------------------\n");
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    nid = -1;
    nid = OBJ_obj2nid(obj);
    printf("obj2nid:%d\n", nid);
    //===========================================================
    printf("---------------------------------------------------------------\n");
    nid = -1;
    nid = OBJ_txt2nid("long name");
    printf("nid:\t%d\n", nid);

    nid = -1;
    nid = OBJ_txt2nid("short name");
    printf("nid:\t%d\n", nid);
    //===========================================================
    ASN1_OBJECT * o = OBJ_txt2obj("long name", 0);
    if(OBJ_cmp(o,obj) == 0)
    {
        printf("o == obj\n");
    }
    else
    {
        printf("o != obj\n");
    }
    
    //============================================================
    char buf[100] = {0};
    int buflen = 100;

    int len = OBJ_obj2txt(buf, buflen, obj, 0);
    printf("obj2txt:");
    for(int i = 0; i < len; i++)
    {
        printf("%c ", buf[i]);
    }
    printf("\n");

    len = OBJ_obj2txt(buf, buflen, obj, 1);
    printf("obj2txt:");
    for(int i = 0; i < len; i++)
    {
        printf("%c ", buf[i]);
    }
    printf("\n");
    
    //====================================
    len = OBJ_length(obj);
    printf("obj size :%d\n", len);
    const unsigned char* data = OBJ_get0_data(obj);
    printf("obj content:");
    for(int i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
    //====================================

    unsigned char der[100] = {0};
    len = a2d_ASN1_OBJECT(der, 100, oid, -1);
    printf("obj    der: ");
    for(int i = 0; i < len; i++)
    {
        printf("%02x ", der[i]);
    }
    printf("\n");
    //======================================
    OBJ_cleanup();
    ASN1_OBJECT_free(obj);
    ASN1_OBJECT_free(o);
}

int main(int argc, char const *argv[])
{
    asn1_der_codec();
    asn1_object_create();
    asn1_a2i_INTEGER();
    asn1_a2i_STRING();
    asn1_bit_string();
    asn1_dup();
    asn1_ENUMERATED();
    asn1_ENUMERATED_to_BN();
    asn1_parse_dump();
    asn1_string_dup();
    asn1_oid_der();
    asn1_STRING_TABLE();
    asn1_obj_util();
    return 0;
}
