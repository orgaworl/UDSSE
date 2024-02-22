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

#define SRE_DEC_FAIL 0
#define SRE_DEC_SUCCESS 1
struct MSK_S
{
    SK_S*sk;
    PP_S*pp;
    H_S*H;
    B_S*B;
};


int SRE_KGen(pairing_t &pairing,int lambda,int b,int h);
int SRE_Enc(pairing_t &pairing,MSK_S*&msk,element_t &m,element_t& t);
int SRE_KRev(pairing_t &pairing,MSK_S*&msk,element_t t[]);
int SRE_Dec(pairing_t &pairing,MSK_S*&msk,CT_S*ct,element_t &tag);
