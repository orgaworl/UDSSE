/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-03 16:13:02
 */
#pragma once
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <string>
// #include <strings>
using namespace std;
// PRF define
#define HASH_VALUE_LENGTH 32
#define PRF_LEN 64
#define TAG_LEN PRF_LEN
// HMAC define
#define MD5_HASH_LENGTH 16
#define SHA256_HASH_LENGTH 32
#define HMAC_MD5_HASH_LENGTH 16
#define HMAC_SHA256_HASH_LENGTH 32

// COMPONENT
int PRF(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen);
string PRF(string Key, string seed);

int hmac(unsigned char *md_value, const char *algorithm, unsigned char *msg, size_t msgLen, unsigned char *key, size_t keyLen);

int HMAC_SHA256(unsigned char Komega[], int len1, unsigned char ST[], int len2, unsigned char UT[]);
int HMAC_MD5(unsigned char Komega[], int len1, unsigned char ST[], int len2, unsigned char stream[]);

int HMAC_SHA256(char Komega[], int len1, char ST[], int len2, char UT[]);
int HMAC_MD5(char Komega[], int len1, char ST[], int len2, char stream[]);

string HMAC_SHA256(string Komega, string ST);
string HMAC_MD5(string Komega, string ST);
