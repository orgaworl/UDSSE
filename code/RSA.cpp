#include "RSA.h"

void generateRSAKey(std::string &pk, std::string &sk)
{
    // 公私密钥对
    size_t pri_len;
    size_t pub_len;
    char *pri_key = NULL;
    char *pub_key = NULL;

    // 生成密钥对
    RSA *keypair = RSA_generate_key(RSA_KEY_LENGTH, RSA_3, NULL, NULL);
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
    // RSA_public_encrypt(clearText.length(), (const unsigned char *)clearText.c_str(), (unsigned char *)encryptedText,rsa,RSA_PADDING);
    if (clearText.length() >= RSA_KEY_LENGTH / 8)
    {
        printf("rsa input overflow. \n");
    }
    int ret = RSA_public_encrypt(
        clearText.length(),
        (const unsigned char *)clearText.c_str(),
        (unsigned char *)encryptedText,
        rsa,
        RSA_PKCS1_PADDING);
        // RSA_NO_PADDING);
    if (ret >= 0)
    {
        strRet = std::string(encryptedText, ret);
    }
    else
    {
        strRet = "";
    }
    // 释放内存
    free(encryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}
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
    int ret = RSA_private_decrypt(cipherText.length(),
                                  (const unsigned char *)cipherText.c_str(),
                                  (unsigned char *)decryptedText,
                                  rsa,
                                  RSA_PKCS1_PADDING);
    // RSA_NO_PADDING);
    if (ret >= 0)
        strRet = std::string(decryptedText, ret);
    else
        strRet = "";
    // 释放内存
    free(decryptedText);
    BIO_free_all(keybio);
    RSA_free(rsa);

    return strRet;
}


int testRSA()
{
    // 原始明文
    std::string srcText = "this is an example";

    std::string encryptText;
    std::string encryptHexText;
    std::string decryptText;

    std::cout << "=== 原始明文 ===" << std::endl;
    std::cout << srcText << std::endl;

    // // rsa
    std::cout << "=== rsa加解密 ===" << std::endl;
    std::string pk, sk;
    generateRSAKey(pk, sk);
    std::cout << "公钥: " << std::endl;
    std::cout << pk << std::endl;
    std::cout << "私钥： " << std::endl;
    std::cout << sk << std::endl;
    // encryptText = rsa_pub_encrypt(srcText, pk);
    // std::cout << "加密字符： " << std::endl;
    // std::cout << encryptText << std::endl;
    // decryptText = rsa_pri_decrypt(encryptText, sk);
    // std::cout << "解密字符： " << std::endl;
    // std::cout << decryptText << std::endl;

    string ST = srcText;
    cout << "-----------------------------------\n";
    for (int j = 0; j < ST.size(); j++)
    {
        cout << hex << (int)(unsigned char)ST[j] << "";
    }
    cout << endl;
    for (int i = 0; i < 10; i++)
    {
        ST = rsa_pri_decrypt(ST, sk);
        cout << "-----------------------------------\n";
        for (int j = 0; j < ST.size(); j++)
        {
            cout << hex << (int)(unsigned char)ST[j] << "";
        }
        cout << endl;
    }
    cout << "******************************************\n";
    cout << "-----------------------------------\n";
    for (int j = 0; j < ST.size(); j++)
    {
        cout << hex << (int)(unsigned char)ST[j] << "";
    }
    cout << endl;
    for (int i = 0; i < 10; i++)
    {
        ST = rsa_pub_encrypt(ST, pk);
        cout << "-----------------------------------\n";
        for (int j = 0; j < ST.size(); j++)
        {
            cout << hex << (int)(unsigned char)ST[j] << "";
        }
        cout << endl;
    }
    system("pause");
    return 0;
}


std::string RsaPubEncrypt(const std::string &clear_text, const std::string &pub_key)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA* rsa = RSA_new();
    // 注意-----第1种格式的公钥
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // 注意-----第2种格式的公钥（这里以第二种格式为例）
    //rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
 
    // 获取RSA单次可以处理的数据块的最大长度
    int key_len = RSA_size(rsa);
    int block_len = key_len - 11;    // 因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11
 
    // 申请内存：存贮加密后的密文数据
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    // 对数据进行分段加密（返回值是加密后数据的长度）
    while (pos < clear_text.length()) {
        sub_str = clear_text.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }
    
    // 释放内存  
    BIO_free_all(keybio);
    RSA_free(rsa);
    delete[] sub_text;
 
    return encrypt_text;
}
std::string RsaPriDecrypt(const std::string &cipher_text, const std::string &pri_key)
{
    std::string decrypt_text;
    RSA *rsa = RSA_new();
    BIO *keybio;
    keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
 
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (rsa == nullptr) {

        return std::string();
    }
 
    // 获取RSA单次处理的最大长度
    int key_len = RSA_size(rsa);
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    // 对密文进行分段解密
    while (pos < cipher_text.length()) {
        sub_str = cipher_text.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            decrypt_text.append(std::string(sub_text, ret));
            printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += key_len;
        }
    }
    // 释放内存  
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
 
    return decrypt_text;
}


std::string RsaPriEncrypt(const std::string &clear_text, std::string &pri_key)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return std::string("");
    }
 
    // 获取RSA单次可以处理的数据块的最大长度
    int key_len = RSA_size(rsa);
    int block_len = key_len - 11;    // 因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11
 
    // 申请内存：存贮加密后的密文数据
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    // 对数据进行分段加密（返回值是加密后数据的长度）
    while (pos < clear_text.length()) {
        sub_str = clear_text.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }
    
    // 释放内存  
    delete sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
 
    return encrypt_text;
}
std::string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key)
{
    std::string decrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA* rsa = RSA_new();
    
    // 注意-------使用第1种格式的公钥进行解密
    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // 注意-------使用第2种格式的公钥进行解密（我们使用这种格式作为示例）
    // rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        return decrypt_text;
    }
 
    // 获取RSA单次处理的最大长度
    int len = RSA_size(rsa);
    char *sub_text = new char[len + 1];
    memset(sub_text, 0, len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    // 对密文进行分段解密
    while (pos < cipher_text.length()) {
        sub_str = cipher_text.substr(pos, len);
        memset(sub_text, 0, len + 1);
        ret = RSA_public_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            decrypt_text.append(std::string(sub_text, ret));
            // printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += len;
        }
    }
 
    // 释放内存  
    delete sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
 
    return decrypt_text;
}


