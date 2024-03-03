/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-03 13:49:14
 */

#include <stdio.h>
#include<iostream>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

#define KEY_LENGTH 2048 // 密钥长度

int RSA_KeyGen();
void generateRSAKey(std::string pk, std::string sk);
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey);
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey);
int testRSA(int argc, char **argv);