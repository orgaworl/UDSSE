/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:10:58
 */
#include"UDSSE.h"

int UDSSE_Setup(int sfd,int lambda,int d)
{
    
}
int UDSSE_Search(int sfd,element_t &K,element_t &omega)
{

}
int UDSSE_Update(int sfd,element_t &K,OP_TYPE op,int id,element_t &omega,element_t &ind)
{

}
int UDSSE_UpdateKey(int sfd,element_t &K,element_t &omega)
{

}



int UDSSE_F(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen)
{
	int hashTimes = (RESULT_LENGTH - 1) / HASH_VALUE_LENGTH + 1;
	for (int i = 0; i < hashTimes; i++)
	{
		unsigned char md_value[HASH_VALUE_LENGTH + 1];
		hmac(md_value, "SHA256", (unsigned char*)seed, seedLen, (unsigned char*)Key, KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			result[i * HASH_VALUE_LENGTH + j] = md_value[j];
		}
		
	}
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