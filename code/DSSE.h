/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-25 21:04:20
 */
#include <stdio.h>
#include <string.h>
#include <list>
#include <ctime>
#include <iostream>
#include "/usr/local/include/pbc/pbc.h"
#include <bits/stdc++.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <vector>
#include <map>
using namespace std;

#define MD5_HASH_LENGTH 16
#define SHA256_HASH_LENGTH 32
#define HMAC_MD5_HASH_LENGTH 16
#define HMAC_SHA256_HASH_LENGTH 32

int HMAC_SHA256(std::string &Komega, std::string &ST, std::string &UT);
int HMAC_MD5(std::string &Komega, std::string &ST, std::string &stream);
class EDB
{
private:
public:
    
    EDB() {}
};