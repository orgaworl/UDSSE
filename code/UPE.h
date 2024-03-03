
#include <stdio.h>
#include <string.h>
#include <list>
#include <ctime>
#include <iostream>
#include "/usr/local/include/pbc/pbc.h"
#include <openssl/sha.h>
using namespace std;

#define DIV_ZERO_ERROR 0
#define SUCESS 1

#define DECRYPT_SUCESS 1
#define DECRYPT_FAIL 0

#define TAG_ZERO 0

class SK_S
{
public:
    int i;
    element_t sk0;
    element_t galpha;
    element_t **SKmain;

    SK_S(int i, pairing_t &pairing)
    {
        this->i = i;
        element_init_G1(sk0, pairing);
        element_init_G1(galpha, pairing);
        SKmain = new element_t *[i + 1];
        for (int loop = 0; loop < i + 1; loop++)
        {
            SKmain[loop] = new element_t[3];
            element_init_G1(SKmain[loop][0], pairing);
            element_init_G1(SKmain[loop][1], pairing);
            element_init_Zr(SKmain[loop][2], pairing);
        }
    }
    SK_S(SK_S *SK, pairing_t &pairing)
    {
        this->i = SK->i;
        element_init_G1(sk0, pairing);
        element_set(sk0, SK->sk0);
        element_init_G1(galpha, pairing);
        element_set(galpha, SK->galpha);
        SKmain = new element_t *[i + 1];
        for (int loop = 0; loop < i + 1; loop++)
        {
            SKmain[loop] = new element_t[3];
            element_init_G1(SKmain[loop][0], pairing);
            element_init_G1(SKmain[loop][1], pairing);
            element_init_Zr(SKmain[loop][2], pairing);
            element_set(SKmain[loop][0], SK->SKmain[loop][0]);
            element_set(SKmain[loop][1], SK->SKmain[loop][1]);
            element_set(SKmain[loop][2], SK->SKmain[loop][2]);
        }
    }
    SK_S()
    {
        this->i = -1;
    }
    ~SK_S()
    {
        element_clear(galpha);
        element_clear(sk0);
        for (int loop = 0; loop < i + 1; loop++)
        {
            element_clear(SKmain[loop][0]);
            element_clear(SKmain[loop][1]);
            element_clear(SKmain[loop][2]);
            delete SKmain[loop];
        }
        delete SKmain;
        SKmain = NULL;
    }
};
class CT_S
{
public:
    char *id;
    int d;
    element_t *CT;
    element_t *tagList;

    CT_S(int d, pairing_t &pairing)
    {
        this->d = d;
        CT = new element_t[d + 2];
        element_init_GT(CT[0], pairing);
        for (long i = 1; i < d + 2; i++)
        {
            element_init_G1(CT[i], pairing);
        }
        tagList = new element_t[d];
        for (long i = 0; i < d; i++)
        {
            element_init_Zr(tagList[i], pairing);
        }
        id = NULL;
    }
    CT_S(CT_S *copy, pairing_t &pairing)
    { // 深复制
        this->d = copy->d;
        CT = new element_t[d + 2];
        element_init_GT(CT[0], pairing);
        element_set(CT[0], copy->CT[0]);
        for (long i = 1; i < d + 2; i++)
        {
            element_init_G1(CT[i], pairing);
            element_set(CT[i], copy->CT[i]);
        }
        tagList = new element_t[d];
        for (long i = 0; i < d; i++)
        {
            element_init_Zr(tagList[i], pairing);
            element_set(tagList[i], copy->tagList[i]);
        }
    }
    ~CT_S()
    {
        for (long i = 0; i < d + 2; i++)
        {
            element_clear(CT[i]);
        }
        for (long i = 0; i < d; i++)
        {
            element_clear(tagList[i]);
        }
        delete[] CT;
        CT=NULL;
        delete[] tagList;
        tagList=NULL;
    }
};
class PP_S
{
public:
    int d;
    element_t *PP;
    PP_S(int d, pairing_t &pairing)
    {
        this->d = d;
        PP = new element_t[d + 3];
        for (long i = 0; i < d + 3; i++)
        {
            element_init_G1(PP[i], pairing);
        }
    }
    PP_S(PP_S *copy, pairing_t &pairing)
    {
        this->d = copy->d;
        PP = new element_t[d + 3];
        for (long i = 0; i < d + 3; i++)
        {
            element_init_G1(PP[i], pairing);
            element_set(PP[i], copy->PP[i]);
        }
    }
    ~PP_S()
    {
        for (long i = 0; i < d + 3; i++)
        {
            element_clear(PP[i]);
        }
        delete[] PP;
        PP=NULL;
    }
};
class token
{
    public:
    element_t d_alpha;
    element_t galpha;
    ~token()
    {
        element_clear(d_alpha);
        element_clear(galpha);
    }
};

int l(pairing_t &pairing, element_t &result, element_t x, long j, element_t *&xc, long degree);

void q(pairing_t &pairing, element_t &result, element_t x, element_t *&xc, element_t *&yc, long d);

int H(element_t &result, element_t &x);

int Hash(element_t &result, unsigned char *str);

//void V(pairing_t &pairing, element_t &result, PP_S *&PP_, element_t x, element_t *&xc, long d);
void V(pairing_t &pairing, element_t &result, PP_S *PP_, element_t x, element_t *&xc, long d);

// 组件
int UPE_Keygen(pairing_t &pairing, long lambda, long d, PP_S *&PP_, SK_S *&SK0);

int UPE_Encrypy(pairing_t &pairing, PP_S *PP_, SK_S *SK, element_t &M, element_t *&TagList, CT_S *&CT_);

int UPE_Puncture(pairing_t &pairing, PP_S *PP, SK_S *&SKi_1, element_t &tag);

int UPE_UPDATE_SK(pairing_t &pairing, PP_S *PP, SK_S *SK, token *&token_to_send);

int UPE_UPDATE_CT(pairing_t &pairing, PP_S *PP, CT_S *CT, token *token);

int UPE_Decrypt(pairing_t &pairing, SK_S *SK, CT_S *CT_, element_t &M);