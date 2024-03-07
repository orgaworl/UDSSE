/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-28 22:09:47
 */
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include "SRE.h"

void INIT(pairing_t &pairing)
{
    char param[1024];
    FILE *file = fopen("../param/a.param", "r");
    size_t count = fread(param, 1, 1024, file);
    fclose(file);
    pairing_init_set_buf(pairing, param, count);
}

int main()
{
    pairing_t pairing;
    INIT(pairing);

    element_t plain;
    element_t M;
    element_init_GT(plain, pairing);
    element_init_GT(M, pairing);
    unsigned char w[128] = "hello,world";
    element_from_bytes(M, w);
    unsigned char buf[120];
    unsigned char *decryptResult = new unsigned char[128];

    int b = 1024;
    int h = 2;
    int d = 1;
    int lambda = 1024;
    CT_S *CT;
    MSK_S *MSK;

    // (3) 明文相关参数
    // 明文tag
    element_t *TagList = new element_t[d];
    for (int i = 0; i < d; i++)
    {
        element_init_Zr(TagList[i], pairing);
        element_set_si(TagList[i], i + 10);
    }
    // (4) U&&P 参数
    // punture 测试使用的tag
    int puncTimes = 10;
    element_t puncTags[1024];
    for (int loop = 0; loop < puncTimes; loop++)
    {
        element_init_Zr(puncTags[loop], pairing);
        element_set_si(puncTags[loop], loop + 10+d);
    }

    // 2.生成MSK
    printf("KEYGEN START\n");
    SRE_KGen(pairing, MSK, lambda, b, h, d);
    

    // 3.使用SK对M进行加密
    printf("ENCRYPT START\n");
    SRE_Enc(pairing, MSK, M, TagList, CT);
    // fprintf(encryT,"%f ",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);

    // 4. puncture
    printf("PUNCTURE \n");
    SRE_KRev(pairing, MSK, puncTags, puncTimes);



    // 6. decrypt
    printf("DECRYPT  \n");
    element_t notPuncTag;
    element_init_Zr(notPuncTag, pairing);
    element_set_si(notPuncTag, 1025);
    int mark=SRE_Dec(pairing, MSK, CT,plain);
    if(mark==SRE_DEC_FAIL)
    {
        printf("Punctured tag !\n");
    }
    else{
        element_to_bytes(decryptResult, plain);
        if (element_cmp(M, plain) == 0)
        {
            printf("***SUCESS DECRYPT***\n");
            printf("PLAINTEXT: \"%s\"\n", decryptResult);
        }
        else
        {
            printf("***FAIL TO DECRYPT***\n");
        }
    }
    return 0;
}