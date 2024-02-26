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
#include "/usr/local/include/pbc/pbc.h"
#include "UPE.h"
#include "BloomFilter.h"
using namespace std;

#define DEFAULT_d 100
#define DEFAULT_lambda 1024
#define DEFAULT_h 5
#define DEFAULT_b 1<<512 //2**512


#define SRE_DEC_FAIL 0
#define SRE_DEC_SUCCESS 1
struct MSK_S
{
    SK_S*sk;
    PP_S*pp;
    H_S*H;
    B_S*B;
};


// int SRE_KGen(pairing_t &pairing,int lambda,int b,int h);
// int SRE_Enc(pairing_t &pairing,MSK_S*&msk,element_t &m,element_t& t);
// int SRE_KRev(pairing_t &pairing,MSK_S*&msk,element_t t[]);
// int SRE_Dec(pairing_t &pairing,MSK_S*&msk,CT_S*ct,element_t &tag);
int SRE_KGen(pairing_t &pairing,MSK_S*msk,int lambda,int b,int h,int lam,int d,element_t &t0);
int SRE_Enc(pairing_t &pairing,MSK_S*&msk,element_t &m,element_t*&tagList,CT_S *&ct);
int SRE_KRev(pairing_t &pairing,MSK_S*&msk,element_t t[],int tagNum);
int SRE_Dec(pairing_t &pairing,MSK_S*&msk,CT_S*ct,element_t &tag,element_t &m);