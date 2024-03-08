/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-03 16:12:56
 */

#include "PRF.h"
int PRF(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen)
{
	int hashTimes = (PRF_LEN - 1) / HASH_VALUE_LENGTH + 1;
	unsigned char *temp = new unsigned char[KeyLen + HASH_VALUE_LENGTH];
	for (int i = 0; i < seedLen; i++)
	{
		temp[i] = seed[i];
	}
	for (int i = 0; i < hashTimes; i++)
	{
		unsigned char A[HASH_VALUE_LENGTH + 1];
		hmac(A, "SHA256", (unsigned char *)seed, seedLen, (unsigned char *)Key, KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			temp[seedLen + j] = A[j];
		}
		hmac(A, "SHA256", (unsigned char *)temp, seedLen + HASH_VALUE_LENGTH, (unsigned char *)Key, KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			result[i * HASH_VALUE_LENGTH + j] = A[j];
		}
	}
	free(temp);
}

string PRF(string Key, string seed)
{

	char result[PRF_LEN];
	int seedLen = seed.length();
	int KeyLen = Key.length();
	int hashTimes = (PRF_LEN - 1) / HASH_VALUE_LENGTH + 1;
	unsigned char *temp = new unsigned char[KeyLen + HASH_VALUE_LENGTH];
	for (int i = 0; i < seedLen; i++)
	{
		temp[i] = seed[i];
	}

	// 计算 PRF 值
	unsigned char A[HASH_VALUE_LENGTH + 1];
	for (int i = 0; i < hashTimes; i++)
	{

		hmac(A, "SHA256", (unsigned char *)seed.c_str(), seedLen, (unsigned char *)Key.c_str(), KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			temp[seedLen + j] = A[j];
		}
		hmac(A, "SHA256", (unsigned char *)temp, seedLen + HASH_VALUE_LENGTH, (unsigned char *)Key.c_str(), KeyLen);
		for (int j = 0; j < HASH_VALUE_LENGTH; j++)
		{
			result[i * HASH_VALUE_LENGTH + j] = A[j];
		}
	}
	free(temp);
	string res = result;
	return res;
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

int HMAC_SHA256(unsigned char Komega[], int len1, unsigned char ST[], int len2, unsigned char UT[])
{
	hmac(UT, "SHA256", ST, len2, Komega, len1);
}
int HMAC_MD5(unsigned char Komega[], int len1, unsigned char ST[], int len2, unsigned char stream[])
{
	hmac(stream, "MD5", ST, len2, Komega, len1);
}

int HMAC_SHA256(char Komega[], int len1, char ST[], int len2, char UT[])
{
	hmac((unsigned char *)UT, "SHA256", (unsigned char *)ST, len2, (unsigned char *)Komega, len1);
}
int HMAC_MD5(char Komega[], int len1, char ST[], int len2, char stream[])
{
	hmac((unsigned char *)stream, "MD5", (unsigned char *)ST, len2, (unsigned char *)Komega, len1);
}

string HMAC_SHA256(string Komega, string ST)
{
	char buf[HMAC_SHA256_HASH_LENGTH];
	hmac((unsigned char *)buf, "SHA256", (unsigned char *)ST.c_str(), ST.length(), (unsigned char *)Komega.c_str(), Komega.length());
	string hmac = buf;
	return hmac;
}
string HMAC_MD5(string Komega, string ST)
{
	char buf[HMAC_MD5_HASH_LENGTH];
	hmac((unsigned char *)buf, "MD5", (unsigned char *)ST.c_str(), ST.length(), (unsigned char *)Komega.c_str(), Komega.length());
	string hmac = buf;
	return hmac;
}