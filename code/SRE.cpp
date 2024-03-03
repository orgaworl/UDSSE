/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 18:35:09
 */
#include "SRE.h"

// #define DEFAULT_lambda 1024
// #define DEFAULT_b 1<<512 //2**512
// #define DEFAULT_h 5
// #define DEFAULT_d 100
// #define MAX_TAG_NUM 100

PP_S *pp;
SK_S *sk;
int SRE_KGen(pairing_t &pairing, MSK_S *&msk, int lambda, int b, int h, int d)
{
    msk = new MSK_S;
    BF_Gen(b, h, msk->H, msk->B);

    // UPE_Keygen(pairing, lambda, d, msk->pp, msk->sk);
    UPE_Keygen(pairing, lambda, d, pp, sk);
    int temp = pp->d;
    return 0;
}
int SRE_Enc(pairing_t &pairing, MSK_S *&msk, element_t &m, element_t *&tagList, CT_S *&ct)
{
    UPE_Encrypy(pairing, msk->pp, msk->sk, m, tagList, ct);
    return 0;
}
int SRE_KRev(pairing_t &pairing, MSK_S *&msk, element_t t[], int tagNum)
{
    // update MSK
    for (int i = 0; i < tagNum; i++)
    {
        // update B
        BF_Update(msk->H, msk->B, t[i]);
        // update SK
        UPE_Puncture(pairing, msk->pp, msk->sk, t[i]);
    }
    return 0;
}
int SRE_Dec(pairing_t &pairing, MSK_S *&msk, CT_S *ct, element_t &tag, element_t &m)
{
    if (BF_Check(msk->H, msk->B, tag))
    {
        return SRE_DEC_FAIL;
    }
    UPE_Decrypt(pairing, msk->sk, ct, m);
    return SRE_DEC_SUCCESS;
}