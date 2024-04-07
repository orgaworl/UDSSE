/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:11:09
 */

#pragma once
#include <stdio.h>
// #include <iostream>
// #include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
// #include <strings.h>
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
// #define CHECK_E 1
// #define CHECK_D 1
// #define PRINT_RESULT 1
// #define NOTE 1
// #define OFFLINE 1
// #define PRINT 1
// #define CHECK_BYTES 1
// #define CHECK_ST 1
#define TRANS_BUF_SIZE 4096
#define MAX_BUF_SIZE 1024
#define IND_LEN 128



// EI
class EI_ENTRY
{
public:
    // element_t tag;
    std::string e;
    // EI_ENTRY()
    // {
    //     e.clear();
    // }
};

class LDB_ENTRY
{
public:
    int c; // update times
    MSK_S *msk;
    vector<element_t *> D;
    std::string ST;
    LDB_ENTRY()
    {
        c = 0;
        msk = NULL;
        D.clear();
        ST.clear();
    }
    ~LDB_ENTRY()
    {
        delete msk;
    }
};

#define EI map<std::string, EI_ENTRY *> // UT -> Entry
#define LDB map<std::string, LDB_ENTRY *> // omega -> Entry
#define EDB map<std::string, std::string> // ind -> omega

// K
#define KEY_LEN 32
#define ST_LEN 32
#define UT_LEN 32

// UPDATE OP define
#define OP_TYPE bool
#define OP_ADD 1
#define OP_DEL 0

// return value
#define UDSSE_Setup_Client_Sucess 1
#define UDSSE_Setup_Client_Fail -1
#define UDSSE_Setup_Server_Sucess 1
#define UDSSE_Setup_Server_Fail -1

#define UDSSE_Search_Client_Sucess 1
#define UDSSE_Search_Client_Fail -1
#define UDSSE_Search_Server_Sucess 1
#define UDSSE_Search_Server_Fail -1

#define UDSSE_Update_Client_Sucess 1
#define UDSSE_Update_Client_Fail -1
#define UDSSE_Update_Server_Sucess 1
#define UDSSE_Update_Server_Fail -1

#define UDSSE_UpdateKey_Client_Sucess 1
#define UDSSE_UpdateKey_Client_Fail -1
#define UDSSE_UpdateKey_Server_Sucess 1
#define UDSSE_UpdateKey_Server_Fail -1

// encode or decode result value
#define DECODE_FAIL NULL
#define ENCODE_FAIL ""

// HASH function define
#define HASH1_LENGTH SHA256_HASH_LENGTH
#define HASH2_LENGTH MD5_HASH_LENGTH

// UDSSE FUNCTION
int UDSSE_Setup_Client(pairing_t &pairing, char *buf, int lambda);
int UDSSE_Setup_Server(pairing_t &pairing, char *buf);
int UDSSE_Search_Client(pairing_t &pairing, char *buf, string omega);
int UDSSE_Search_Server(pairing_t &pairing, char *buf);
int UDSSE_Update_Client(pairing_t &pairing, char *buf, OP_TYPE op, string omega, string ind,int d=1);
int UDSSE_Update_Server(pairing_t &pairing, char *buf);

int UDSSE_UpdateKey_Client(pairing_t &pairing, char *buf, string omega);
int UDSSE_UpdateKey_Server(pairing_t &pairing, char *buf);

string SK2Bytes(SK_S *sk);
string PP2Bytes(PP_S *pp);
string H2Bytes(H_S *h);
string B2Bytes(B_S *b);
string MSK2Bytes(MSK_S *msk);
string CT2Bytes(CT_S *ct);

SK_S *Bytes2SK(pairing_t &pairing, char *bytes);
PP_S *Bytes2PP(pairing_t &pairing, char *bytes);
H_S *Bytes2H(char *bytes);
B_S *Bytes2B(char *bytes);
MSK_S *Bytes2MSK(pairing_t &pairing, char *bytes);
CT_S *Bytes2CT(pairing_t &pairing, string bytes);
string Token2Bytes(token *tk);
token *Bytes2Token(pairing_t &pairing, char *bytes);