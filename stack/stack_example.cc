#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/safestack.h>



typedef struct Student_st
{
    char    *name;
    int     age;
    char    *otherInfo;
} Student;

DEFINE_SPECIAL_STACK_OF(StackName, Student)

Student *itemMalloc()
{
    Student *a = (Student *)malloc(sizeof(Student));
    a->name = (char*)malloc(20);
    strcpy(a->name, "zcp");
    a->age = 20;
    a->otherInfo = (char*)malloc(20);
    strcpy(a->otherInfo, "no info");
    return a;
}

void itemFree(Student *a)
{
    free(a->name);
    free(a->otherInfo);
    free(a);
}

static int itemCmp(const Student* const* a,  const Student* const* b)
{
    int ret;
    ret = strcmp((*a)->name, (*b)->name);
    return ret;
}


int main()
{
    STACK_OF(StackName) *s, *snew;
    Student *s1, *one, *s2, *s3;
    int i, num;
    

    s = sk_StackName_new_null();
    snew = sk_StackName_new(itemCmp);
    s2 = itemMalloc();
    s3 = itemMalloc();
    sk_StackName_push(snew, s2);
    i = sk_StackName_find(snew, s2);
    s1 = itemMalloc();
    sk_StackName_push(s, s1);
    sk_StackName_push(s, s3);
    sk_StackName_sort(s);
    num = sk_StackName_num(s);
    for (i = 0; i < num; i++)
    {
        one = sk_StackName_value(s, i);
        printf("student name : %s\n", one->name);
        printf("sutdent age : %d\n", one->age);
        printf("student otherinfo : %s\n\n\n", one->otherInfo);
    }
    sk_StackName_pop_free(s, itemFree);
    sk_StackName_pop_free(snew, itemFree);
    return 0;
}