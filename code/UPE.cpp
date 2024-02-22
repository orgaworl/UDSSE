
// #include <stdio.h>
// #include <string.h>
// #include<list>
// #include<ctime>
// #include <iostream>
// #include "/usr/local/include/pbc/pbc.h"
// #include <openssl/sha.h>
// using namespace std;
#include "UPE.h"

int l(pairing_t &pairing, element_t &result, element_t x, long j, element_t *&xc, long degree)
{
    // 发生在Zr上
    element_t tempZr1;
    element_t tempZr2;
    element_t tempResult;
    element_init_Zr(tempZr1, pairing);
    element_init_Zr(tempZr2, pairing);
    element_init_Zr(tempResult, pairing);

    element_set1(tempResult); // 累乘初始值1
    for (long m = 0; m <= degree; m++)
    {
        if (m != j)
        {
            element_sub(tempZr1, x, xc[m]);
            element_sub(tempZr2, xc[j], xc[m]);
            if (element_is0(tempZr2))
            {
                element_set_si(result, 0);
                return DIV_ZERO_ERROR;
            }
            element_div(tempZr1, tempZr1, tempZr2);
            element_mul(tempResult, tempResult, tempZr1);
        }
    }
    element_set(result, tempResult);

    element_clear(tempZr1);
    element_clear(tempZr2);
    element_clear(tempResult);
    return SUCESS;
}
void q(pairing_t &pairing, element_t &result, element_t x, element_t *&xc, element_t *&yc, long d)
{
    // 发生在Zr上
    element_t tempZr;
    element_t tempResult;
    element_init_Zr(tempZr, pairing);
    element_init_same_as(tempResult, result);

    element_set0(tempResult); // 累加结果初始化为0
    for (int j = 0; j <= d; j++)
    {
        l(pairing, tempZr, x, j, xc, d);
        element_mul(tempZr, tempZr, yc[j]);
        element_add(tempResult, tempResult, tempZr);
    }
    element_set(result, tempResult);

    element_clear(tempResult);
    element_clear(tempZr);
}
int H(element_t &result, element_t &x)
{
    // Hash函数,使用openssl sha256.取HASH value前20Byte
    int length = element_length_in_bytes(x);
    unsigned char *byteData = new unsigned char[length];
    element_to_bytes(byteData, x);

    unsigned char hashValue[33] = {0};
    SHA256((const unsigned char *)byteData, length, hashValue);
    element_from_bytes(result, hashValue);

    return 1;
}
int Hash(element_t &result, unsigned char *str)
{
    // Hash函数,使用openssl sha256.取HASH value前20Byte
    int length = strlen((char *)str);
    unsigned char hashValue[33] = {0};
    SHA256((const unsigned char *)str, length, hashValue);
    element_from_bytes(result, hashValue);

    return 1;
}
void V(pairing_t &pairing, element_t &result, PP_S *&PP_, element_t x, element_t *&xc, long d)
{
    // G1
    element_t tempResult;
    element_t tempZr;
    element_t tempG1;
    element_init_Zr(tempZr, pairing);
    element_init_G1(tempG1, pairing);
    element_init_G1(tempResult, pairing);
    element_set1(tempResult); // 累乘结果初始化为1
    element_t *PP = PP_->PP;
    for (int i = 0; i <= d; i++)
    {
        l(pairing, tempZr, x, i, xc, d);
        element_pow_zn(tempG1, PP[i + 2], tempZr);
        element_mul(tempResult, tempResult, tempG1);
    }
    element_set(result, tempResult);

    element_clear(tempZr);
    element_clear(tempG1);
    element_clear(tempResult);
}

// 组件
int UPE_Keygen(pairing_t &pairing, long k, long d, element_t &t0, PP_S *&PP_, SK_S *&SK0)
{
    // k           安全参数
    // d           tag总数
    // t0          从未用到的tag_0
    // PP[3+d]    (3+d)长数组
    // SK0[1][4]  1*4矩阵

    element_t tempZr;
    element_t tempG1;
    element_init_Zr(tempZr, pairing);
    element_init_G1(tempG1, pairing);
    // 1.
    // p阶循环群G1=G2=<g>
    element_t g;              // G1
    element_t alpha, beta, r; // Zp
    element_init_G1(g, pairing);
    element_init_Zr(alpha, pairing);
    element_init_Zr(beta, pairing);
    element_init_Zr(r, pairing);
    element_random(g);
    element_random(alpha);
    element_random(beta);
    element_random(r);

    // 2. 随机生成d次多项式q(x):
    // xList =[0,1,...,d]
    // qxList=[q(0), q(1),...q(d)]
    long coffLength = d + 1;
    element_t *qxList = new element_t[coffLength];
    element_t *xList = new element_t[coffLength];
    element_init_Zr(qxList[0], pairing);
    element_init_Zr(xList[0], pairing);
    element_set(qxList[0], beta);
    element_set_si(xList[0], 0);
    for (int power = 1; power <= d; power++)
    {
        element_init_Zr(qxList[power], pairing);
        element_random(qxList[power]);
        element_init_Zr(xList[power], pairing);
        element_set_si(xList[power], power);
    }

    // 3.计算公钥PP
    PP_ = new PP_S(d, pairing);
    element_t *PP = PP_->PP;
    // 3.1 PP[0:3]
    element_init_G1(PP[0], pairing);
    element_init_G1(PP[1], pairing);
    element_init_G1(PP[2], pairing);
    element_set(PP[0], g);
    element_pow_zn(PP[1], g, alpha);
    element_pow_zn(PP[2], g, beta);

    // 3.2 PP[3:d+3]
    for (long i = 3; i < d + 3; i++)
    {
        // 已知q(x) for x in [0,1,...,d]的值, 直接使用
        element_init_G1(PP[i], pairing);
        element_pow_zn(PP[i], g, qxList[i - 2]);
    }

    // 4. 计算私钥SK0
    SK0 = new SK_S(0, pairing);
    element_add(tempZr, alpha, r);
    element_pow_zn(SK0->sk0, PP[2], tempZr); //
    H(tempZr, t0);
    V(pairing, tempG1, PP_, tempZr, xList, d);
    element_pow_zn(SK0->SKmain[0][0], tempG1, r); //
    element_pow_zn(SK0->SKmain[0][1], g, r);      //
    element_set(SK0->SKmain[0][2], t0);           //

    element_pow_zn(SK0->galpha, g, alpha);

    element_clear(tempZr);
    element_clear(tempG1);
    element_clear(g);
    element_clear(alpha);
    element_clear(beta);
    element_clear(r);
    return 1;
}

int UPE_Encrypy(pairing_t &pairing, PP_S *&PP_, SK_S *SK, element_t &M, element_t *&TagList, CT_S *&CT_)
{
    // CT[2+d]    2+d长的密文
    // TagList[d] 除t0以外所有的tag

    element_t tempZr; // 暂存计算中间结果,加速运算
    element_t tempGT; // 暂存计算中间结果,加速运算
    element_t tempG1; // 暂存计算中间结果,加速运算
    element_init_GT(tempGT, pairing);
    element_init_Zr(tempZr, pairing);
    element_init_G1(tempG1, pairing);

    element_t g;
    element_t g1;
    element_t g2;
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_set(g, PP_->PP[0]);
    element_set(g1, PP_->PP[1]);
    element_set(g2, PP_->PP[2]);

    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);
    long d = PP_->d;

    // xc=[0,1,2, ..., d]
    element_t *xc = new element_t[d + 1];
    for (int i = 0; i <= d; i++)
    {
        element_init_Zr(xc[i], pairing);
        element_set_si(xc[i], i);
    }

    // 1. 计算密文CT=[    ]  ,  其中根据公钥PP可插值计算V(x)
    CT_ = new CT_S(d, pairing);
    element_t *CT = CT_->CT;
    // CT[0]
    element_init_GT(CT[0], pairing);
    pairing_apply(tempGT, SK->galpha, g2, pairing);
    element_pow_zn(tempGT, tempGT, s);
    element_mul(CT[0], M, tempGT); //
    // CT[1]
    element_init_G1(CT[1], pairing);
    element_pow_zn(CT[1], g, s); //
    // other CT[i]
    for (long i = 2; i < d + 2; i++)
    {
        element_init_G1(CT[i], pairing);
        H(tempZr, TagList[i - 2]);
        V(pairing, tempG1, PP_, tempZr, xc, d);
        element_pow_zn(CT[i], tempG1, s);
    }

    for (int i = 0; i < d; i++)
    {
        element_set(CT_->tagList[i], TagList[i]);
    }

    element_clear(tempZr);
    element_clear(tempGT);
    element_clear(tempG1);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    element_clear(s);
    return 1;
}

int UPE_Puncture(pairing_t &pairing, PP_S *&PP, SK_S *&SKi_1, element_t &tag)

{
    // PP   [3+d]      (3+d)长数组
    // tag          Puncture所用tag
    // SKi-1[i][4]
    // SKi  [i+1][4]

    element_t tempG1; // 暂存计算中间结果,加速运算
    element_t tempZr; // 暂存计算中间结果,加速运算
    element_init_G1(tempG1, pairing);
    element_init_Zr(tempZr, pairing);

    element_t g;
    element_t g1;
    element_t g2;
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_set(g, PP->PP[0]);
    element_set(g1, PP->PP[1]);
    element_set(g2, PP->PP[2]);

    element_t lambda, r0, r1;
    element_init_Zr(lambda, pairing);
    element_init_Zr(r0, pairing);
    element_init_Zr(r1, pairing);
    element_random(lambda);
    element_random(r0);
    element_random(r1);
    long d = PP->d;

    // xc=[0,1,2, ..., d]
    element_t *xc = new element_t[d + 1];
    for (int i = 0; i <= d; i++)
    {
        element_init_Zr(xc[i], pairing);
        element_set_si(xc[i], i);
    }

    // 1. 计算SK_i=[sk_0',sk_1, ... ,sk_{i-1},sk_i ]
    // 1.1  sk_1, ... ,sk_{i-1}   (深拷贝)
    int i = SKi_1->i + 1;
    SK_S *SKi = new SK_S(i, pairing);
    long loop = 1;
    for (loop = 1; loop < i; loop++)
    {
        for (int in = 0; in < 3; in++)
        {
            element_set(SKi->SKmain[loop][in], SKi_1->SKmain[loop][in]);
        }
    }
    // 1.2  sk_i
    loop = i;
    H(tempZr, tag);
    V(pairing, tempG1, PP, tempZr, xc, d);
    element_pow_zn(SKi->SKmain[loop][0], tempG1, r1); //
    element_pow_zn(SKi->SKmain[loop][1], g, r1);      //
    element_set(SKi->SKmain[loop][2], tag);           //

    // 1.3 sk_0'
    H(tempZr, SKi_1->SKmain[0][2]);
    V(pairing, tempG1, PP, tempZr, xc, d);
    element_pow_zn(tempG1, tempG1, r0);
    element_mul(SKi->SKmain[0][0], SKi_1->SKmain[0][0], tempG1); //
    element_pow_zn(tempG1, g, r0);
    element_mul(SKi->SKmain[0][1], SKi_1->SKmain[0][1], tempG1); //
    element_set(SKi->SKmain[0][2], SKi_1->SKmain[0][2]);         //

    // 1.4 the one
    element_add(tempZr, r0, r1);
    element_pow_zn(tempG1, g2, tempZr);
    element_mul(SKi->sk0, SKi_1->sk0, tempG1);

    // 1.5 other one
    element_set(SKi->galpha, SKi_1->galpha);

    delete SKi_1;
    SKi_1 = SKi; // 将输入指针重指向新SK;

    element_clear(tempG1);
    element_clear(tempZr);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    element_clear(lambda);
    element_clear(r0);
    element_clear(r1);
    return 1;
}

int UPE_UPDATE_SK(pairing_t &pairing, PP_S *PP, SK_S *&SK, token *&token_to_send)
{
    cout << "mark1";
    // 0. parameters
    int i = SK->i;
    int d = PP->d;
    element_t g;
    element_t g2;
    element_init_G1(g, pairing);
    element_init_G1(g2, pairing);
    element_set(g, PP->PP[0]);
    element_set(g2, PP->PP[2]);

    element_t tempG1;
    element_t tempZr;
    element_t sum_delta_r;

    element_init_G1(tempG1, pairing);
    element_init_Zr(tempZr, pairing);
    element_init_Zr(sum_delta_r, pairing);

    // xc=[0,1,2, ..., d]
    element_t *xc = new element_t[d + 1];
    for (int i = 0; i <= d; i++)
    {
        element_init_Zr(xc[i], pairing);
        element_set_si(xc[i], i);
    }

    // 1. generate delta
    element_t d_alpha;
    element_t *d_r = new element_t[i + 1];
    element_init_Zr(d_alpha, pairing);
    element_random(d_alpha);

    element_set_si(sum_delta_r, 0);
    for (int loop = 0; loop <= i; loop++)
    {
        element_init_Zr(d_r[loop], pairing);
        element_random(d_r[loop]);
        element_add(sum_delta_r, sum_delta_r, d_r[loop]);
    }
    cout << "mark2";
    // 2. set token
    token_to_send = new token;
    element_init_Zr(token_to_send->d_alpha, pairing);
    element_set(token_to_send->d_alpha, d_alpha);

    element_init_G1(token_to_send->galpha, pairing);
    element_set(token_to_send->galpha, SK->galpha);

    cout << "mark3";
    // 3. update SK
    // 单独项1
    element_add(tempZr, d_alpha, sum_delta_r);
    element_pow_zn(tempG1, PP->PP[2], tempZr);
    element_mul(SK->sk0, SK->sk0, tempG1);
    // 单项2
    element_pow_zn(tempG1, PP->PP[0], d_alpha);
    element_mul(SK->galpha, SK->galpha, tempG1);
    // i*3 部分
    for (int loop = 0; loop <= i; loop++)
    {

        H(tempZr, SK->SKmain[loop][2]);
        V(pairing, tempG1, PP, tempZr, xc, d);
        element_pow_zn(tempG1, tempG1, d_r[loop]);
        element_mul(SK->SKmain[loop][0], SK->SKmain[loop][0], tempG1); //

        element_pow_zn(tempG1, PP->PP[0], d_r[loop]);
        element_mul(SK->SKmain[loop][1], SK->SKmain[loop][1], tempG1); //
    }

    element_clear(tempG1);
    element_clear(tempZr);
    element_clear(d_alpha);
    element_clear(sum_delta_r);
    return 1;
}

int UPE_UPDATE_CT(pairing_t &pairing, PP_S *&PP, CT_S *&CT, token *&token)
{
    int d = PP->d;
    if (d != CT->d)
    {
        cout << "INVALID PARAMETERS"
             << "IN UPDATE CT" << endl;
        return 0;
    }
    // 0. parameters
    element_t g;
    element_t g1;
    element_t g2;
    element_t d_s;
    element_t tempG1;
    element_t tempZr;
    element_t tempGT1;
    element_init_G1(g, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);

    element_init_Zr(d_s, pairing);
    element_init_G1(tempG1, pairing);
    element_init_Zr(tempZr, pairing);
    element_init_GT(tempGT1, pairing);
    element_set(g, PP->PP[0]);
    element_set(g1, PP->PP[1]);
    element_set(g2, PP->PP[2]);
    element_random(d_s);
    element_t *tagList = CT->tagList;
    // xc=[0,1,2, ..., d]
    element_t *xc = new element_t[d + 1];
    for (int i = 0; i <= d; i++)
    {
        element_init_Zr(xc[i], pairing);
        element_set_si(xc[i], i);
    }

    // 1. update CT
    pairing_apply(tempGT1, token->galpha, g2, pairing);
    element_pow_zn(tempGT1, tempGT1, d_s);
    element_mul(CT->CT[0], CT->CT[0], tempGT1); //

    pairing_apply(tempGT1, CT->CT[1], g2, pairing);
    element_pow_zn(tempGT1, tempGT1, token->d_alpha);
    element_mul(CT->CT[0], CT->CT[0], tempGT1); //

    pairing_apply(tempGT1, g, g2, pairing);
    element_pow_zn(tempGT1, tempGT1, d_s);
    element_pow_zn(tempGT1, tempGT1, token->d_alpha);
    element_mul(CT->CT[0], CT->CT[0], tempGT1);

    // ct_2
    element_pow_zn(tempG1, g, d_s);
    element_mul(CT->CT[1], CT->CT[1], tempG1); //

    // ct^{(3,1)} - ct^{(3,d)}
    for (int loop = 2; loop <= d + 1; loop++)
    {
        H(tempZr, tagList[loop - 2]); // tag_1 - tag_d
        V(pairing, tempG1, PP, tempZr, xc, d);
        element_pow_zn(tempG1, tempG1, d_s);
        element_mul(CT->CT[loop], CT->CT[loop], tempG1); //
    }

    element_clear(tempGT1);
    element_clear(tempG1);
    element_clear(tempZr);
    element_clear(g);
    element_clear(g1);
    element_clear(g2);
    element_clear(d_s);
    return 1;
}

int UPE_Decrypt(pairing_t &pairing, SK_S *&SK, CT_S *&CT_, element_t &M)
{

    element_t tempGT1;
    element_t tempGT2;
    element_t tempGT3;
    element_t tempZr;
    element_init_GT(tempGT1, pairing);
    element_init_GT(tempGT2, pairing);
    element_init_GT(tempGT3, pairing);
    element_init_Zr(tempZr, pairing);
    element_t *&tagList = CT_->tagList;
    long i = SK->i;
    long d = CT_->d;

    // 1. 插值计算d+1个系数\omega_i for i in range(0,d)

    // tempList= [t_1, ..., t_d, ... sk^{(4)}]
    element_t *tempList = new element_t[d + 1];
    for (int k = 0; k < d; k++)
    {
        element_init_Zr(tempList[k], pairing);
        H(tempZr, tagList[k]);
        element_set(tempList[k], tempZr);
    }
    element_init_Zr(tempList[d], pairing);

    // omega= [omega_{*}, omega_1, ..., omega_d ]
    int respose;
    element_t **omega = new element_t *[i + 1];
    for (int j = 0; j <= i; j++)
    {
        omega[j] = new element_t[d + 1];
        H(tempZr, SK->SKmain[j][2]);
        element_set(tempList[d], tempZr);

        element_init_Zr(omega[j][0], pairing);
        element_set_si(tempZr, 0);
        respose = l(pairing, omega[j][0], tempZr, d, tempList, d);
        if (respose == DIV_ZERO_ERROR)
        {
            return DECRYPT_FAIL;
        }
        for (long k = 1; k <= d; k++)
        {
            element_init_Zr(omega[j][k], pairing);
            element_set_si(tempZr, 0);
            respose = l(pairing, omega[j][k], tempZr, k - 1, tempList, d);
            if (respose == DIV_ZERO_ERROR)
            {
                return DECRYPT_FAIL;
            }
        }
    }

    // 2. 计算Z_j  for 0<=j<=i ,并将结果累乘
    element_t *CT = CT_->CT;
    element_t prodZ;
    element_t tempG1_2;
    element_t tempG1_1;
    element_init_GT(prodZ, pairing);
    element_init_G1(tempG1_2, pairing);
    element_init_G1(tempG1_1, pairing);

    element_set1(prodZ);
    for (long j = 0; j <= i; j++)
    {
        // pairing_apply(tempGT1, SK->sk0, CT[1], pairing);
        element_set_si(tempGT1, 1); //

        element_set1(tempG1_1);
        for (long k = 1; k <= d; k++)
        {
            element_pow_zn(tempG1_2, CT[k + 1], omega[j][k]);
            element_mul(tempG1_1, tempG1_1, tempG1_2);
        }
        pairing_apply(tempGT2, SK->SKmain[j][1], tempG1_1, pairing);

        pairing_apply(tempGT3, SK->SKmain[j][0], CT[1], pairing);
        element_pow_zn(tempGT3, tempGT3, omega[j][0]);
        element_div(tempGT1, tempGT1, tempGT2);
        element_div(tempGT1, tempGT1, tempGT3);
        element_mul(prodZ, prodZ, tempGT1);
    }
    // // 3. 计算明文M
    element_div(M, CT[0], prodZ);
    pairing_apply(tempGT1, SK->sk0, CT[1], pairing);
    element_div(M, M, tempGT1);

    element_clear(tempGT1);
    element_clear(tempGT2);
    element_clear(tempGT3);
    element_clear(prodZ);
    element_clear(tempG1_1);
    element_clear(tempG1_2);
    for (int j = 0; j <= i; j++)
    {
        delete[] omega[j];
    }
    delete[] omega;
    return DECRYPT_SUCESS;
}
