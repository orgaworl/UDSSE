/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:00:27
 */

#include "BloomFilter.h"
int Hash2Int(element_t &x, int HashChoice)
{

    char buf[1024];
    int length = element_to_bytes((unsigned char *)buf, x);
    // printf("%lld\n",length);
    char res[256];
    switch (HashChoice)
    {
    case 1:
        SHA256((const unsigned char *)buf, length, (unsigned char *)res);
        break;
    case 2:
        MD4((const unsigned char *)buf, length, (unsigned char *)res);
        break;
    case 3:
        MD5((const unsigned char *)buf, length, (unsigned char *)res);
        break;
    default:
        // SHA1((const unsigned char *)buf, length, (unsigned char *)res);
        break;
    }

    // int HashValInt;
    // printf("%d",hashValue[0]);
    //  HashValInt=hashValue[0];
    // HashValInt = *(unsigned int *)hashValue;

    return *(int *)res;
}

int BF_Gen(int b, int h, H_S *&H, B_S *&B)
{
    // return H and B
    H = new H_S(h);
    // H->main=new int [h];

    B = new B_S;
    // B->b=b;
    // B->main=new char [b];
    B->main = new std::bitset<b_MAX_VALUE>();

    return 0;
}
int BF_Update(H_S *&H, B_S *&B, element_t &x)
{
    int loop = H->h;
    int hashValue = 0;
    for (int i = 0; i < loop; i++)
    {
        // 计算Hash值

        hashValue = Hash2Int(x, i);
        hashValue = hashValue % b_MAX_VALUE;
        if (hashValue < 0)
        {
            hashValue += b_MAX_VALUE;
        }
        //printf("%d\n",hashValue);
        B->main->set(hashValue,true);
    }

    return 0;
}
int BF_Check(H_S *&H, B_S *&B, element_t &x)
{

    int loop = H->h;
    for (int i = 0; i < loop; i++)
    {
        // 计算Hash值
        uint hashValue = Hash2Int(x, i);
        if (B->main[hashValue % b_MAX_VALUE] == false)
        {
            return BF_CHECK_FALSE;
        }
    }
    return BF_CHECK_TRUE;
}
int BF_Free(H_S *&H, B_S *&B)
{
    if (H != NULL)
    {
        // delete H->main;
        delete H;
        H = NULL;
    }
    if (B != NULL)
    {
        delete B->main;
        delete B;
        B = NULL;
    }
    return 0;
}