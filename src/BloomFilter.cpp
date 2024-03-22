/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:00:27
 */

#include "../include/BloomFilter.h"

unsigned int Hash2Int(element_t &x, int HashChoice)
{

    char buf[128];
    int length = element_to_bytes((unsigned char *)buf, x);
    // printf("%lld\n",length);
    char res[64];
    int digestLen = 0;
    switch (HashChoice)
    {
    case 0:
        SHA1((const unsigned char *)buf, length, (unsigned char *)res);
        digestLen = SHA_DIGEST_LENGTH;
        break;
    case 1:
        SHA256((const unsigned char *)buf, length, (unsigned char *)res);
        digestLen = SHA256_DIGEST_LENGTH;
        break;
    case 2:
        MD4((const unsigned char *)buf, length, (unsigned char *)res);
        digestLen = MD4_DIGEST_LENGTH;
        break;
    case 3:
        MD5((const unsigned char *)buf, length, (unsigned char *)res);
        digestLen = MD5_DIGEST_LENGTH;
        break;
    default:
        printf("not supported hash function %d\n",HashChoice);
        break;

    }
    unsigned int index=0;
    char*poi=res;
    for(int i=0;i<digestLen;i+=sizeof(int))
    {
        index=index ^ *(unsigned int *)poi;
        poi+=sizeof(int);

    }
    return index;
    //return *(unsigned int *)res;
}

int BF_Gen(int b, int h, H_S *&H, B_S *&B)
{
    // return H and B
    H = new H_S(h);
    B = new B_S;
    B->main = new std::bitset<b_MAX_VALUE>();
    return 0;
}
int BF_Update(H_S *&H, B_S *&B, element_t &x)
{
    int loop = H->h;
    unsigned int hashValue = 0;
    for (int i = 0; i < loop; i++)
    {
        // cal Hash
        hashValue = Hash2Int(x, i);
        hashValue = hashValue % b_MAX_VALUE;
        //printf("BF update hash value: %d\n",hashValue);
        B->main->set(hashValue, true);
    }

    return 0;
}
int BF_Check(H_S *&H, B_S *&B, element_t &x)
{

    int loop = H->h;
    unsigned int hashValue = 0;
    for (int i = 0; i < loop; i++)
    {
        // cal hash
        hashValue = Hash2Int(x, i);
        hashValue = hashValue % b_MAX_VALUE;
        //printf("BF check hash value: %d\n", hashValue);
        if (B->main->test(hashValue) == false)
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