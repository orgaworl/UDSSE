/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 18:35:15
 */
// #include <stdio.h>
// #include <string.h>
// #include <list>
// #include <ctime>
// #include <iostream>
#pragma once
#include "/usr/local/include/pbc/pbc.h"
#include <vector>
#include "UPE.h"
#include "BloomFilter.h"
using namespace std;

#define DEFAULT_lambda 1024
#define DEFAULT_b 1 << 512 // 2**512
#define DEFAULT_h 5
// #define DEFAULT_d 100
#define MAX_TAG_NUM 100

#define SRE_DEC_FAIL 0
#define SRE_DEC_SUCCESS 1
class MSK_S
{
public:
    SK_S *sk;
    PP_S *pp;
    H_S *H;
    B_S *B;
    MSK_S()
    {
        sk = NULL;
        pp = NULL;
        H = NULL;
        B = NULL;
    }
    MSK_S(MSK_S *&copy, pairing_t &pairing)
    {
        sk = new SK_S(copy->sk, pairing);
        pp = new PP_S(copy->pp, pairing);
        H = new H_S(copy->H);
        B = new B_S(copy->B);
        // cout<<sk->i<<endl;
        // cout<<pp->d<<endl;
    }
    ~MSK_S()
    {
        if (sk != NULL)
        {
            delete sk;
            sk = NULL;
        }
        if (pp != NULL)
        {
            delete pp;
            pp = NULL;
        }
        if (H != NULL)
        {
            delete H;
            H = NULL;
        }
        if (B != NULL)
        {
            delete B;
            B = NULL;
        }
    }
};

int SRE_KGen(pairing_t &pairing, MSK_S *&msk, int lambda, int b, int h, int d);
int SRE_Enc(pairing_t &pairing, MSK_S *msk, element_t &m, element_t *&tagList, CT_S *&ct);
int SRE_KRev(pairing_t &pairing, MSK_S *msk, element_t t[], int tagNum);
int SRE_KRev(pairing_t &pairing, MSK_S *msk, vector<element_t *> &tagList);
int SRE_Dec(pairing_t &pairing, MSK_S *msk, CT_S *ct, element_t &m);