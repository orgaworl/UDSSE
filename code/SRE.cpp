/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 18:35:09
 */
#include"SRE.h"

int SRE_KGen(pairing_t &pairing,int lambda,int b,int h,int lam,int d,element_t &t0,MSK_S*msk)
{
    msk=new MSK_S;
    BF_Gen(b,h,msk->H,msk->B);
    UPE_Keygen(pairing,lam,d,t0,msk->pp,msk->sk);
    return 0;
}
int SRE_Enc(pairing_t &pairing,MSK_S*&msk,element_t &m,element_t*&tagList,CT_S *&ct;)
{
    UPE_Encrypy(pairing,msk->pp,msk->sk,m,tagList,ct);
    return 0;
}
int SRE_KRev(pairing_t &pairing,MSK_S*&msk,element_t t[],int tagNum)
{
    //update MSK
    for(int i=0,i<tagNum;i++)
    {
        // update B
        BF_Update(msk->H,msk->B,t[i]); 
        // update SK          
        UPE_Puncture(pairing,msk->pp,msk->sk,t[i]);
    }
    return 0;
    
}
int SRE_Dec(pairing_t &pairing,MSK_S*&msk,CT_S*ct,element_t &tag,element_t &m)
{
    if(BF_Check())
    {
        return SRE_DEC_FAIL;
    }
    UPE_Decrypt(pairing,msk->sk,ct,m);
    return SRE_DEC_SUCCESS;
}