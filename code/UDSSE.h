/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:11:09
 */
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <list>
#include <ctime>
#include <bits/stdc++.h>
#include <vector>
#include <map>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "openssl/tls1.h"
#include "/usr/local/include/pbc/pbc.h"
#include "SRE.h"
#include "RSA.h"
using namespace std;

class EDB
{
private:
public:
    EDB() {}
};

struct mapValPair
{
    int c; //update times
    MSK_S *msk;
    vector<element_t>*D;
};
map<string, mapValPair> MAP;

#define KEY_LEN_IN_BYTE 32
char *K;
char *Kt;
char *Ks;

int lambda_ = 1024;
int d_ = 4;
int b_ = 64;
int h_ = 4;


// UPDATE OP DEFINE
#define OP_TYPE bool
#define OP_ADD 1
#define OP_DEL 0
// PRF DEFINE
#define HASH_VALUE_LENGTH 32
#define RESULT_LENGTH 64
// HMAC DEFINE
#define MD5_HASH_LENGTH 16
#define SHA256_HASH_LENGTH 32
#define HMAC_MD5_HASH_LENGTH 16
#define HMAC_SHA256_HASH_LENGTH 32

// UDSSE FUNCTION
int UDSSE_Setup_Client(pairing_t &pairing, int sfd, int lambda, int d);
int UDSSE_Search_Client(pairing_t &pairing, int sfd, char *omega);
int UDSSE_Update_Client(pairing_t &pairing, int sfd, OP_TYPE op, char *omega, char *ind);
int UDSSE_UpdateKey_Client(pairing_t &pairing, int sfd, char *omega);



// COMPONENT
int PRF(unsigned char *result, char *Key, int KeyLen, char *seed, int seedLen);
int hmac(unsigned char *md_value, const char *algorithm, unsigned char *msg, size_t msgLen, unsigned char *key, size_t keyLen);


int HMAC_SHA256(std::string &Komega, std::string &ST, std::string &UT);
int HMAC_MD5(std::string &Komega, std::string &ST, std::string &stream);
