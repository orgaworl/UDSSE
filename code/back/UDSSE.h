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
#include <openssl/evp.h>
#include "openssl/tls1.h"
#include "/usr/local/include/pbc/pbc.h"
#include "SRE.h"
#include "RSA.h"
#include "PRF.h"
using namespace std;

// K
#define KEY_LEN 32
#define ST_LEN 32
#define UT_LEN 32
struct K_S
{
    string Kt;
    string Ks;
};
K_S K;

// EDB & EDB_cache
struct EDB_ENTRY
{
    element_t tag;
    std::string e;
};
#define EDB map<std::string, EDB_ENTRY> // UT -> Entry
EDB edb;
EDB edb_cache;


// Local DB
struct LDB_ENTRY
{
    int c; // update times
    MSK_S *msk;
    vector<element_t> D;
    std::string ST;
};
#define LDB map<std::string, LDB_ENTRY> // omega -> Entry
LDB ldb;


int lambda_ = 1024;
int b_ = 64;
int h_ = 4;




// UPDATE OP define
#define OP_TYPE bool
#define OP_ADD 1
#define OP_DEL 0

// HASH function define
#define HASH1_LENGTH MD5_HASH_LENGTH
#define HASH2_LENGTH SHA256_HASH_LENGTH

// UDSSE FUNCTION
int UDSSE_Setup_Client(pairing_t &pairing, int sfd, int lambda, int d);
int UDSSE_Search_Client(pairing_t &pairing, int sfd, char *omega);
int UDSSE_Update_Client(pairing_t &pairing, int sfd, OP_TYPE op, char *omega, char *ind);
int UDSSE_UpdateKey_Client(pairing_t &pairing, int sfd, char *omega);

int UDSSE_Setup_Server(pairing_t &pairing, int sfd);
int UDSSE_Search_Server(pairing_t &pairing, int sfd);
int UDSSE_Update_Server(pairing_t &pairing, int sfd, OP_TYPE op);
int UDSSE_UpdateKey_Server(pairing_t &pairing, int sfd);


