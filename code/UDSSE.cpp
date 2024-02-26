/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:10:58
 */
#include"UDSSE.h"


int UDSSE_Setup(pairing_t &pairing,int sfd,int lambda,int d)
{
    // element_init_G1(K,pairing);
    // element_random(K);
    // lambda_=lambda;
    // d_=d;
	K=new char[KEY_LEN_IN_BYTE];
	Kt=new char[KEY_LEN_IN_BYTE];
	Ks=new char[KEY_LEN_IN_BYTE];
	for(int i=0;i<KEY_LEN_IN_BYTE;i++)
	{
		K[i]=rand();
		Kt[i]=rand();
		Ks[i]=rand();
	}
    return 0;
}
int UDSSE_Search(pairing_t &pairing,int sfd,char*omega)
{




}
int UDSSE_Update(pairing_t &pairing,int sfd,OP_TYPE op,char* &omega,char* ind)
{
    mapValPair *temp=&(MAP[omega]);
    
    if(temp==nullptr)
    {
        SRE_KGen(pairing,temp->msk,lambda_,b_,h_,d_);
		temp->i=0;
		temp->D.clear();
    }
	// 计算PRF值
	unsigned char PRF_Val[HASH_VALUE_LENGTH];
	int inputLen=strlen(omega)+strlen(ind);
	char *inputText=new char[inputLen+1];
	UDSSE_F(PRF_Val,Kt,KEY_LEN_IN_BYTE,inputText,inputLen);

	// 计算tag并转化到ECC上
	element_t tag;
	element_init_G1(tag,pairing);
	element_from_hash(tag,PRF_Val,HASH_VALUE_LENGTH);
	element_t *tagList;
	tagList=&tag;

	// 更新
	if(op==OP_ADD)
	{
		// 计算密文
		element_t plain;
		element_init_G1(plain,pairing);
		element_from_hash(plain,ind,strlen(ind));
		CT_S *ct;
		SRE_Enc(pairing,temp->msk,plain,tagList,ct);
		// TODO 
		





	}
	else if(op==OP_DEL)
	{
		temp->D.push_back(tag);
	}
	else
	{
		printf("NOT SUPPORTED OPERATION ! ");
	}


}
int UDSSE_UpdateKey(pairing_t &pairing,int sfd,char *omega)
{


}















int UDSSE_F(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen)
{
	int hashTimes = (RESULT_LENGTH - 1) / HASH_VALUE_LENGTH + 1;
	unsigned char *temp=new unsigned char[KeyLen+HASH_VALUE_LENGTH];
	for(int i=0;i<seedLen;i++)
	{
		temp[i]=seed[i];
	}
	for (int i = 0; i < hashTimes; i++)
	{
		unsigned char A[HASH_VALUE_LENGTH + 1];
		hmac(A, "SHA256", (unsigned char*)seed, seedLen, (unsigned char*)Key, KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			temp[seedLen+j] = A[j];
		}
		hmac(A, "SHA256", (unsigned char*)temp, seedLen+HASH_VALUE_LENGTH, (unsigned char*)Key, KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			result[i*HASH_VALUE_LENGTH+j] = A[j];
		}
	}
	free(temp);
}

int hmac(unsigned char *md_value, const char *algorithm, unsigned char *msg, size_t msgLen, unsigned char *key, size_t keyLen)
{
	if (algorithm == NULL || msg == NULL || key == NULL)
	{
		printf("%s %d %s: parameter error\n", __FILE__, __LINE__, __func__);
		exit(1);
	}
	const EVP_MD *md = EVP_get_digestbyname(algorithm);
	if (md == NULL)
	{
		printf("%s %d %s: unknown message digest: %s\n", __FILE__, __LINE__, __func__, algorithm);
		exit(1);
	}

	// unsigned char md_value[EVP_MAX_MD_SIZE] = "";
	unsigned int md_len = 0;

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, keyLen, md, NULL);
	HMAC_Update(&ctx, msg, msgLen);
	HMAC_Final(&ctx, md_value, &md_len);
	HMAC_CTX_cleanup(&ctx);
#else
	HMAC_CTX *ctx;
	ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, keyLen, md, NULL);
	HMAC_Update(ctx, (const unsigned char *)msg, msgLen);
	HMAC_Final(ctx, md_value, &md_len);
	HMAC_CTX_free(ctx);
#endif
}