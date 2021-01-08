#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/lhash.h>
#include <openssl/bio.h>

typedef struct Student_st
{
    char name[20];
    int age;
    char otherInfo[200];
} Student;

DECLARE_LHASH_HASH_FN(item, Student);
DECLARE_LHASH_COMP_FN(item, Student);
DECLARE_LHASH_DOALL_ARG_FN(item, Student, int);

DEFINE_LHASH_OF(Student);


unsigned long item_hash(const Student *a)
{
    unsigned long hashCode = 0;
    for(int i = 0; i < strlen(a->name); i++)
    {
        hashCode += (a->name[i] << i*8);
    }
    return hashCode;
}
IMPLEMENT_LHASH_HASH_FN(item, Student);

int item_cmp(const Student* a, const Student* b)
{
    const char *namea = a->name;
    const char *nameb = b->name;
    return strcmp(namea, nameb);
}
IMPLEMENT_LHASH_COMP_FN(item, Student);


void item_print_arg(Student* a, int* flag)
{
    printf("%s:flag:%d name:%s\n",__func__, *flag, a->name);
}
IMPLEMENT_LHASH_DOALL_ARG(Student, int);


void item_print(Student* a)
{
    printf("%s:name:%s age:%d otherinfo:%s\n",__func__, a->name, a->age, a->otherInfo);
}

void item_release(Student* a)
{
    printf("%s: name:%s\n",__func__, a->name);
}

int main(int argc, char*argv[])
{
    int flag = 1;
    BIO* f = BIO_new_file("hstable_state.txt", "w+");
    Student s[] = 
    {
            {"zcp", 28, "hu bei"},
            {"forxy", 28, "no info"},
            {"skp", 24, "student"},
            {"zhao_zcp", 28, "zcp's name"},
    };

    Student sr = {"skp", 0, ""};

    LHASH_OF(Student)* htable = lh_Student_new(item_hash, item_cmp);
    if(htable == NULL)
    {
        printf("htable is null\n");
        return -1;
    }

    for(int i = 0; i < sizeof(s)/sizeof(s[0]); i++)
    {
        Student *newItem = lh_Student_insert(htable, &s[i]);

        if(lh_Student_error(htable) && !newItem)
        {
            printf("insert item fail\n");
        }
    }

    printf("num of item:%ld\n", lh_Student_num_items(htable));
    lh_Student_node_usage_stats_bio(htable, f);
    printf("=================================================\n");
    lh_Student_doall(htable, item_print);

    Student* retri = lh_Student_retrieve(htable, &sr);
    printf("=================================================\n");
    item_print(retri);

    printf("=================================================\n");
    retri = lh_Student_delete(htable , &sr);

    lh_Student_doall_int(htable, item_print_arg, &flag);

    lh_Student_node_usage_stats_bio(htable, f);
    printf("=================================================\n");
    lh_Student_doall(htable, item_release);

    BIO_free(f);
    lh_Student_free(htable);

    return 0;
}
