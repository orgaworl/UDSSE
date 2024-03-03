/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-25 21:04:15
 */
#include"DSSE.h"

/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-01 14:27:26
 */
#include "DSSE.h"
#include <openssl/rsa.h>
#include <string>
using namespace std;
#define KEY_LENGTH 2048 // 密钥长度

#include <openssl/rsa.h>

int RSA_KeyGen()
{

    RSA *r;
    int bits = 512, ret;
    unsigned long e = RSA_3;
    BIGNUM *bne;
    r = RSA_generate_key(bits, e, NULL, NULL);
    RSA_print_fp(stdout, r, 11);
    RSA_free(r);
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1)
    {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }

    RSA_free(r);

    return 0;
}

void generateRSAKey(std::string pk, std::string sk)
{
    // 公私密钥对
    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    // 生成密钥对
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    // 获取长度
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // 密钥对读取到字符串
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    // 存储密钥对
    pk = pub_key;
    sk = pri_key;

    // 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）
    // FILE *pubFile = fopen(PUB_KEY_FILE, "w");
    // if (pubFile == NULL)
    // {
    //     assert(false);
    //     return;
    // }
    // fputs(pub_key, pubFile);
    // fclose(pubFile);

    // FILE *priFile = fopen(PRI_KEY_FILE, "w");
    // if (priFile == NULL)
    // {
    //     assert(false);
    //     return;
    // }
    // fputs(pri_key, priFile);
    // fclose(priFile);

    // 内存释放
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

// 命令行方法生成公私钥对（begin public key/ begin private key）
// 找到openssl命令行工具，运行以下
// openssl genrsa -out prikey.pem 1024
// openssl rsa - in privkey.pem - pubout - out pubkey.pem

// 公钥加密
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey)
{
    std::string strRet;
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);
    // 此处有三种方法
    // 1, 读取内存里生成的密钥对，再从内存生成rsa
    // 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa
    // 3，直接从读取文件指针生成rsa
    RSA *pRSAPublicKey = RSA_new();
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

    int len = RSA_size(rsa);
    char *encryptedText = (char *)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // 加密函数
    int ret = RSA_public_encrypt(clearText.length(), (const unsigned char *)clearText.c_str(), (unsigned char *)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);

    // 释放内存
    free(encryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}

// 私钥解密
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)
{
    std::string strRet;
    RSA *rsa = RSA_new();
    BIO *keybio;
    keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);

    // 此处有三种方法
    // 1, 读取内存里生成的密钥对，再从内存生成rsa
    // 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa
    // 3，直接从读取文件指针生成rsa
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

    int len = RSA_size(rsa);
    char *decryptedText = (char *)malloc(len + 1);
    memset(decryptedText, 0, len + 1);

    // 解密函数
    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char *)cipherText.c_str(), (unsigned char *)decryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(decryptedText, ret);

    // 释放内存
    free(decryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}

int main(int argc, char **argv)
{
    // 原始明文
    std::string srcText = "this is an example";

    std::string encryptText;
    std::string encryptHexText;
    std::string decryptText;

    std::cout << "=== 原始明文 ===" << std::endl;
    std::cout << srcText << std::endl;

    // // md5
    // std::cout << "=== md5哈希 ===" << std::endl;
    // md5(srcText, encryptText, encryptHexText);
    // std::cout << "摘要字符： " << encryptText << std::endl;
    // std::cout << "摘要串： " << encryptHexText << std::endl;

    // // sha256
    // std::cout << "=== sha256哈希 ===" << std::endl;
    // sha256(srcText, encryptText, encryptHexText);
    // std::cout << "摘要字符： " << encryptText << std::endl;
    // std::cout << "摘要串： " << encryptHexText << std::endl;

    // // des
    // std::cout << "=== des加解密 ===" << std::endl;
    // std::string desKey = "12345";
    // encryptText = des_encrypt(srcText, desKey);
    // std::cout << "加密字符： " << std::endl;
    // std::cout << encryptText << std::endl;
    // decryptText = des_decrypt(encryptText, desKey);
    // std::cout << "解密字符： " << std::endl;
    // std::cout << decryptText << std::endl;

    // rsa
    std::cout << "=== rsa加解密 ===" << std::endl;
    std::string pk, sk;
    generateRSAKey(pk, sk);
    std::cout << "公钥: " << std::endl;
    std::cout << pk << std::endl;
    std::cout << "私钥： " << std::endl;
    std::cout << sk << std::endl;
    encryptText = rsa_pub_encrypt(srcText, key[0]);
    std::cout << "加密字符： " << std::endl;
    std::cout << encryptText << std::endl;
    decryptText = rsa_pri_decrypt(encryptText, key[1]);
    std::cout << "解密字符： " << std::endl;
    std::cout << decryptText << std::endl;

    system("pause");
    return 0;
}

int DSSE_SETUP(int lambda, std::string pk, std::string sk, std::string key)
{
    generateRSAKey(pk, sk);

    return 0;
}
int DSSE_Search()
{
    std::string Ks;
    std::string omega;
    std::string K_omega;
    PRF(Ks, omega, K_omega);
    // PRF(K,omega,K_omega);
    // std::map<std::string,> W;
    // W

    long long c;
    std::string ST;
    std::string stream;
    std::string cipher;
    // server
    vector<std::string>Res;
    std::string UT(SHA256_HASH_LENGTH, 0);
    for (long long i = 0; i <= c; i++)
    {
        HMAC_SHA256(K_omega, ST, UT);
        HMAC_MD5(K_omega, ST, stream);
        int len=cipher.length();
        std::string plain(len, 0);
        for (int i = 0; i < len; i++)
        {
            plain[i] = cipher[i] ^ stream[i % MD5_HASH_LENGTH];
        }
        Res.push_back(plain);
        ST = rsa_pub_encrypt(ST, pk);
    }
    return 0;
}
int DSSE_Update(std::string &plain)
{
    std::string Komega;
    std::string ST;
    std::string UT;
    std::string stream;
    HMAC_SHA256(Komega, ST, UT);
    HMAC_MD5(Komega, ST, stream);

    // 异或
    int len = plain.length();
    std::string cipher(len, '\0');
    for (int i = 0; i < len; i++)
    {
        cipher[i] = plain[i] ^ stream[i % MD5_HASH_LENGTH];
    }

    // send UT and cipher to server

    return 0;
}

int main()
{

    return 0;
}