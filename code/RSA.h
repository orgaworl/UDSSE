/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-03 13:49:14
 */
#pragma once
//#include <stdio.h>
#include<iostream>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

#define RSA_KEY_LENGTH 2048 // 密钥长度


void generateRSAKey(std::string &pk, std::string &sk);
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey);
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey);
int testRSA();

#define PK_generate generateRSAKey
#define PK_encrypt rsa_pri_decrypt
#define PK_decrypt rsa_pub_encrypt