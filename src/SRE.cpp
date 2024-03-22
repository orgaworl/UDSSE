/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 18:35:09
 */
#include "../include/SRE.h"

// #define DEFAULT_lambda 1024
// #define DEFAULT_b 1<<512 //2**512
// #define DEFAULT_h 5
// #define DEFAULT_d 100
// #define MAX_TAG_NUM 100

// 生成MSK,用以加密具有d个tag的明文
int SRE_KGen(pairing_t &pairing, MSK_S *&msk, int lambda, int b, int h, int d)
{
    // printf("hash num=%d",h);
    msk = new MSK_S();
    BF_Gen(b, h, msk->H, msk->B);
    UPE_Keygen(pairing, lambda, d, msk->pp, msk->sk);
    return 0;
}

// 使用MSK加密具有d个tag(即tagList[d])的明文
int SRE_Enc(pairing_t &pairing, MSK_S *msk, element_t &m, element_t *&tagList, CT_S *&ct)
{
    UPE_Encrypy(pairing, msk->pp, msk->sk, m, tagList, ct);
    return 0;
}

// 对 MSK 撤销对于 tagNum 个 tag(即t[tagNum]) 的解密能力
int SRE_KRev(pairing_t &pairing, MSK_S *msk, element_t tagList[], int tagNum)
{
    // update MSK
    for (int i = 0; i < tagNum; i++)
    {
        // update B
        BF_Update(msk->H, msk->B, tagList[i]);
        // update SK
        UPE_Puncture(pairing, msk->pp, msk->sk, tagList[i]);
    }
    return 0;
}
int SRE_KRev(pairing_t &pairing, MSK_S *msk, vector<element_t *> &tagList)
{
    // update MSK
    int tagNum = tagList.size();
    for (int i = 0; i < tagNum; i++)
    {
        // update B
        BF_Update(msk->H, msk->B, *tagList[i]);
        // update SK
        UPE_Puncture(pairing, msk->pp, msk->sk, *tagList[i]);
    }
    return 0;
}

// 使用 MSK
int SRE_Dec(pairing_t &pairing, MSK_S *msk, CT_S *ct, element_t &m)
{
    int len = ct->d;
    for (int i = 0; i < len; i++)
    {
        if (BF_Check(msk->H, msk->B, ct->tagList[i]))
        {
            return SRE_DEC_FAIL;
        }
    }
    UPE_Decrypt(pairing, msk->sk, ct, m);
    return SRE_DEC_SUCCESS;
}