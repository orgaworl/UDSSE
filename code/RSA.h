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
/*
70e93ea141e1fc673e17e97eadc6b968f385c2aecb03bfb32af3c54ec18db5c
*/

#define RSA_KEY_LENGTH 1024 // 密钥长度


void generateRSAKey(std::string &pk, std::string &sk);
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey);
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey);

std::string RsaPubEncrypt(const std::string &clear_text, const std::string &pub_key);
std::string RsaPriDecrypt(const std::string &cipher_text, const std::string &pri_key);

// contrast
std::string RsaPriEncrypt(const std::string &clear_text, std::string &pri_key);
std::string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key);


int testRSA();

#define PK_generate generateRSAKey
#define PK_encrypt rsa_pri_decrypt
#define PK_decrypt rsa_pub_encrypt
