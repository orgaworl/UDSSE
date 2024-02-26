/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:11:09
 */

// #include <stdio.h>
// #include <string.h>
// #include <list>
// #include <ctime>
// #include <iostream>
#include "/usr/local/include/pbc/pbc.h"
#include "openssl/tls1.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include"SRE.h"
#include <map>
#include <vector>
using namespace std;


struct mapValPair
{
    MSK_S msk;
    int i;
    vector<element_t> D;
};
map<string,mapValPair> MAP;
element_t K;
int lambda_;
int d_;


#define OP_TYPE bool
#define OP_ADD 1
#define OP_DEL 0



int UDSSE_Setup(pairing_t &pairing,int sfd,int lambda,int d);
int UDSSE_Search(pairing_t &pairing,int sfd,element_t &omega,int i);
int UDSSE_Update(pairing_t &pairing,int sfd,OP_TYPE op,char* &omega,element_t& ind);
int UDSSE_UpdateKey(pairing_t &pairing,int sfd,element_t &omega);




#define HASH_VALUE_LENGTH 32
#define RESULT_LENGTH 64

int UDSSE_F(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen);
int hmac(unsigned char *md_value, const char *algorithm, unsigned char *msg, size_t msgLen, unsigned char *key, size_t keyLen);