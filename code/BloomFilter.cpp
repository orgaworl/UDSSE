/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:00:27
 */

#include"BloomFilter.h"

int Hash2Int(element_t &x,int HashChoice)
{
    int length = element_length_in_bytes(x);
    unsigned char *byteData = new unsigned char[length];
    element_to_bytes(byteData, x);

    unsigned char hashValue[33] = {0};
    switch (HashChoice)
    {
        case 1:
            SHA256((const unsigned char *)byteData, length, hashValue);
            break;
        case 2:
            MD4((const unsigned char *)byteData, length, hashValue);
            break;
        case 3:
            MD5((const unsigned char *)byteData, length, hashValue);
            break;
        default:
            SHA1((const unsigned char *)byteData, length, hashValue);

            break;
    }
    uint HashValInt=0;
    return HashValInt;
}

// int accessB(B_S *&B,uint hashValue,int val)
// {
//     if(hashValue/8>=(B->b))
//     {
//         return -1;//越界
//     }
//     if(val==1)
//     {   // 或1
//         B->main[hashValue/8]|=(1<<(hashValue%8));
//     }
//     else if(val==0)
//     {   // 与0
//         B->main[hashValue/8]&=~(1<<(hashValue%8));
//     }
//     return (B->main[hashValue/8] & (1<<(hashValue%8))) !=0;
// }

int BF_Gen(int b,int h,H_S *&H,B_S *&B)
{
    //return H and B
    H=new H_S;
    H->h=h;
    H->main=new int [h];

    B=new B_S;
    B->b=b;
    //B->main=new char [b];
    B->main= new std::bitset<b_MAX_VALUE>();

    return 0;
}
int BF_Update(H_S *&H,B_S *&B,element_t &x) 
{
    int loop=H->h;
    for(int i=0;i<loop;i++)
    {
        //计算Hash值
        uint hashValue=Hash2Int(x,H->main[i]);
        //accessB(B,hashValue,1);
        B->main[hashValue]=true;
        
    }

    return 0;
}
int BF_Check(H_S *&H,B_S *&B,element_t &x)
{
    
    int loop=H->h;
    for(int i=0;i<loop;i++)
    {
        //计算Hash值
        uint hashValue=Hash2Int(x,H->main[i]);
        if(B->main[hashValue]==false)
        {
            return BF_CHECK_FALSE;
        }
    }
    return BF_CHECK_TRUE;

}
int BF_Free(H_S *&H,B_S *&B)
{
    if(H!=NULL)
    {
        delete H->main;
        delete H;
        H=NULL;
    }
    if(B!=NULL)
    {
        delete B->main;
        delete B;
        B=NULL;
    }
    return 0;
}