#include <stdio.h>
#include <string.h>
#include<list>
#include<ctime>
#include <iostream>
#include "/usr/local/include/pbc/pbc.h"

#include <openssl/sha.h>

using namespace std;

#define DIV_ZERO_ERROR 0
#define SUCESS 1

#define DECRYPT_SUCESS 1
#define DECRYPT_FAIL 0


//FILE *poi = fopen("./output.txt", "w+");
// FILE *encryT = fopen("./time/encryT.txt", "w+");
// FILE *puncT = fopen("./time/puncT.txt", "w+");
// FILE *updateT = fopen("./time/updateT.txt", "w+");
// FILE *decryT = fopen("./time/decryT.txt", "w+");

int base=10;
time_t startT;
time_t endT;


// 1.1 初始化双线性对
pairing_t pairing;
void INIT()
{
  char param[1024];
  FILE *file = fopen("./param/a.param", "r");
  size_t count = fread(param, 1, 1024, file);
  fclose(file);
  pairing_init_set_buf(pairing, param, count);
}

class SK_S
{
  public:
  int i;
  element_t sk0;
  element_t galpha;
  element_t**SKmain;

  SK_S(int i)
  {
    this->i=i;
    element_init_G1(sk0,pairing);
    element_init_G1(galpha,pairing);
    SKmain=new element_t*[i+1];
    for(int loop=0;loop<i+1;loop++)
    {
      SKmain[loop]=new element_t[3];
      element_init_G1(SKmain[loop][0],pairing);
      element_init_G1(SKmain[loop][1],pairing);
      element_init_Zr(SKmain[loop][2],pairing);
    }
  }
  SK_S(SK_S *SK)
  {
    this->i=SK->i;
    element_init_G1(sk0,pairing);
    element_set(sk0,SK->sk0);
    element_init_G1(galpha,pairing);
    element_set(galpha,SK->galpha);
    SKmain=new element_t*[i+1];
    for(int loop=0;loop<i+1;loop++)
    {
      SKmain[loop]=new element_t[3];
      element_init_G1(SKmain[loop][0],pairing);
      element_init_G1(SKmain[loop][1],pairing);
      element_init_Zr(SKmain[loop][2],pairing);
      element_set(SKmain[loop][0],SK->SKmain[loop][0]);
      element_set(SKmain[loop][1],SK->SKmain[loop][1]);
      element_set(SKmain[loop][2],SK->SKmain[loop][2]);
    }
  }
  SK_S()
  {
    this->i=-1;
  }
  ~SK_S()
  {
    element_clear(galpha);
    element_clear(sk0);
    for(int loop=0;loop<i+1;loop++)
    {
      element_clear(SKmain[loop][0]);
      element_clear(SKmain[loop][1]);
      element_clear(SKmain[loop][2]);
      delete SKmain[loop];
    }
    delete SKmain;
  }

};
class CT_S
{
  public:
  char*id;
  int d;
  element_t*CT;
  element_t*tagList;

  CT_S(int d)
  {
    this->d=d;
    CT = new element_t[d + 2];
    element_init_GT(CT[0], pairing);
    for (long i = 1; i < d + 2; i++){
      element_init_G1(CT[i], pairing);
    }
    tagList=new element_t[d];
    for (long i = 0; i < d ; i++){
      element_init_Zr(tagList[i], pairing);
    }
    id=NULL;
  }
  CT_S(CT_S *copy)
  { //深复制
    this->d=copy->d;
    CT = new element_t[d + 2];
    element_init_GT(CT[0], pairing);
    element_set(CT[0],copy->CT[0]);
    for (long i = 1; i < d + 2; i++){
      element_init_G1(CT[i], pairing);
      element_set(CT[i],copy->CT[i]);
    }
    tagList=new element_t[d];
    for (long i = 0; i < d ; i++){
      element_init_Zr(tagList[i], pairing);
      element_set(tagList[i], copy->tagList[i]);
    }
  }
  ~CT_S()
  {
    for (long i = 0; i < d + 2; i++)
    {
      element_clear(CT[i]);
    }
    for (long i = 0; i < d ; i++)
    {
      element_clear(tagList[i]);
    }
    delete []CT;
    delete[] tagList;
  }
};
class PP_S
{
  public:
  int d;
  element_t*PP;
  PP_S(int d)
  {
    this->d=d;
    PP = new element_t[d + 3];
    for (long i = 0; i < d + 3; i++)
    {
      element_init_G1(PP[i], pairing);
    }
  }
  PP_S(PP_S*copy)
  {
    this->d=copy->d;
    PP = new element_t[d + 3];
    for (long i = 0; i < d + 3; i++)
    {
      element_init_G1(PP[i], pairing);
      element_set(PP[i], copy->PP[i]);
    }
  }
  ~PP_S()
  {
    for (long i = 0; i < d + 3; i++)
    {
      element_clear(PP[i]);
    }
    delete []PP;
  }
};
struct token
{
  element_t d_alpha;
  element_t galpha;;

};

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
      if(element_is0(tempZr2))
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
  unsigned char *byteData=new unsigned char[length];
  element_to_bytes(byteData, x);

  unsigned char hashValue[33] = {0};  
  SHA256((const unsigned char *)byteData, length, hashValue);
  element_from_bytes(result,hashValue);

  return 1;
}
int Hash(element_t &result,unsigned char*str)
{
  // Hash函数,使用openssl sha256.取HASH value前20Byte
  int length = strlen((char*)str);
  unsigned char hashValue[33] = {0};  
  SHA256((const unsigned char *)str, length, hashValue);
  element_from_bytes(result,hashValue);

  return 1;
}
void V(pairing_t &pairing, element_t &result, PP_S*&PP_, element_t x, element_t *&xc, long d)
{
  // G1
  element_t tempResult;
  element_t tempZr;
  element_t tempG1;
  element_init_Zr(tempZr, pairing);
  element_init_G1(tempG1, pairing);
  element_init_G1(tempResult, pairing);
  element_set1(tempResult); // 累乘结果初始化为1
  element_t*PP=PP_->PP;
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

//组件
int UPDSSE_Keygen(pairing_t &pairing, long k, long d, element_t &t0, PP_S *&PP_, SK_S*&SK0)
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
  //xList =[0,1,...,d]
  //qxList=[q(0), q(1),...q(d)]
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
  PP_=new PP_S(d); 
  element_t*PP = PP_->PP;
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
  SK0=new SK_S(0);
  element_add(tempZr, alpha, r);
  element_pow_zn(SK0->sk0, PP[2], tempZr); //
  H(tempZr, t0);
  V(pairing, tempG1, PP_, tempZr, xList, d);
  element_pow_zn(SK0->SKmain[0][0], tempG1, r); //
  element_pow_zn(SK0->SKmain[0][1], g, r);      //
  element_set(SK0->SKmain[0][2], t0);           //
  

  element_pow_zn(SK0->galpha,g,alpha);


  
  element_clear(tempZr);
  element_clear(tempG1);
  element_clear(g);
  element_clear(alpha);
  element_clear(beta);
  element_clear(r);
  return 1;
}

int UPDSSE_Encrypy(pairing_t &pairing, PP_S*&PP_, SK_S*SK,element_t &M, element_t *&TagList, CT_S *&CT_)
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
  long d=PP_->d;

  // xc=[0,1,2, ..., d]
  element_t *xc = new element_t[d + 1];
  for (int i = 0; i <= d; i++){
    element_init_Zr(xc[i], pairing);
    element_set_si(xc[i], i);
  }

  // 1. 计算密文CT=[    ]  ,  其中根据公钥PP可插值计算V(x)
  CT_=new CT_S(d);
  element_t* CT = CT_->CT;
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

  for(int i=0;i<d;i++)
  {
    element_set(CT_->tagList[i],TagList[i]);
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

int UPDSSE_Puncture(pairing_t &pairing, PP_S *&PP,SK_S*&SKi_1,element_t &tag)

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
  long d=PP->d;


  // xc=[0,1,2, ..., d]
  element_t *xc = new element_t[d + 1];
  for (int i = 0; i <= d; i++){
    element_init_Zr(xc[i], pairing);
    element_set_si(xc[i], i);
  }

  // 1. 计算SK_i=[sk_0',sk_1, ... ,sk_{i-1},sk_i ]
  // 1.1  sk_1, ... ,sk_{i-1}   (深拷贝)
  int i=SKi_1->i+1;
  SK_S*SKi=new SK_S(i);
  long loop=1;
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
  element_set(SKi->SKmain[0][2], SKi_1->SKmain[0][2]); //

  //1.4 the one
  element_add(tempZr, r0, r1);
  element_pow_zn(tempG1, g2, tempZr); 
  element_mul(SKi->sk0, SKi_1->sk0, tempG1);

  //1.5 other one
  element_set(SKi->galpha,SKi_1->galpha);


  delete SKi_1;
  SKi_1=SKi;//将输入指针重指向新SK;
  

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

int UPDSSE_UPDATE_SK(pairing_t &pairing,PP_S* PP,SK_S* &SK,token* &token_to_send)
{
    cout<<"mark1";
  //0. parameters
  int i=SK->i;
  int d= PP->d;
  element_t g;
  element_t g2;
  element_init_G1(g,pairing);
  element_init_G1(g2,pairing);
  element_set(g,PP->PP[0]);
  element_set(g2,PP->PP[2]);

  element_t tempG1; 
  element_t tempZr; 
  element_t sum_delta_r;

  element_init_G1(tempG1, pairing);
  element_init_Zr(tempZr, pairing);
  element_init_Zr(sum_delta_r, pairing);

  // xc=[0,1,2, ..., d]
  element_t *xc = new element_t[d + 1];
  for (int i = 0; i <= d; i++){
    element_init_Zr(xc[i], pairing);
    element_set_si(xc[i], i);
  }
  

  //1. generate delta
  element_t d_alpha;
  element_t *d_r=new element_t[i+1];
  element_init_Zr(d_alpha,pairing);
  element_random(d_alpha);

  element_set_si(sum_delta_r, 0);
  for(int loop=0;loop<=i;loop++)
  {
    element_init_Zr(d_r[loop],pairing);
    element_random(d_r[loop]);
    element_add(sum_delta_r,sum_delta_r,d_r[loop]);
  }
  cout<<"mark2";
  //2. set token
  token_to_send=new token;
  element_init_Zr(token_to_send->d_alpha,pairing);
  element_set(token_to_send->d_alpha,d_alpha);

  element_init_G1(token_to_send->galpha,pairing);
  element_set(token_to_send->galpha,SK->galpha);

cout<<"mark3";
  //3. update SK
  //单独项1
  element_add(tempZr,d_alpha,sum_delta_r);
  element_pow_zn(tempG1,PP->PP[2],tempZr);
  element_mul(SK->sk0,SK->sk0,tempG1);
  //单项2
  element_pow_zn(tempG1,PP->PP[0],d_alpha);
  element_mul(SK->galpha,SK->galpha,tempG1);
  //i*3 部分
  for(int loop=0;loop<=i;loop++)
  {

    H(tempZr,SK->SKmain[loop][2]);
    V(pairing,tempG1,PP,tempZr,xc,d);
    element_pow_zn(tempG1,tempG1,d_r[loop]);
    element_mul(SK->SKmain[loop][0],SK->SKmain[loop][0],tempG1);//

    element_pow_zn(tempG1,PP->PP[0],d_r[loop]);
    element_mul(SK->SKmain[loop][1],SK->SKmain[loop][1],tempG1);//

  }


  
  element_clear(tempG1);
  element_clear(tempZr);
  element_clear(d_alpha);
  element_clear(sum_delta_r);
  return 1;
}

int UPDSSE_UPDATE_CT(pairing_t &pairing,PP_S *&PP,CT_S*&CT,token* &token)
{
  int d=PP->d;
  if (d!=CT->d){
    cout<<"INVALID PARAMETERS"<<"IN UPDATE CT"<<endl;
    return 0;
  }
  //0. parameters
  element_t g;
  element_t g1;
  element_t g2;
  element_t d_s;
  element_t tempG1; 
  element_t tempZr; 
  element_t tempGT1;
  element_init_G1(g,pairing);
  element_init_G1(g1,pairing);
  element_init_G1(g2,pairing);

  element_init_Zr(d_s,pairing);
  element_init_G1(tempG1, pairing);
  element_init_Zr(tempZr, pairing);
  element_init_GT(tempGT1, pairing);
  element_set(g,PP->PP[0]);
  element_set(g1,PP->PP[1]);
  element_set(g2,PP->PP[2]);
  element_random(d_s);
  element_t*tagList=CT->tagList;
  // xc=[0,1,2, ..., d]
  element_t *xc = new element_t[d + 1];
  for (int i = 0; i <= d; i++){
    element_init_Zr(xc[i], pairing);
    element_set_si(xc[i], i);
  }


  //1. update CT
    pairing_apply(tempGT1,token->galpha,g2,pairing);
  element_pow_zn(tempGT1,tempGT1,d_s);
  element_mul(CT->CT[0],CT->CT[0],tempGT1);//

    pairing_apply(tempGT1,CT->CT[1],g2,pairing);
  element_pow_zn(tempGT1,tempGT1,token->d_alpha);
  element_mul(CT->CT[0],CT->CT[0],tempGT1);//

    pairing_apply(tempGT1,g,g2,pairing);
  element_pow_zn(tempGT1,tempGT1,d_s);
  element_pow_zn(tempGT1,tempGT1,token->d_alpha);
  element_mul(CT->CT[0],CT->CT[0],tempGT1);

  //ct_2
  element_pow_zn(tempG1,g,d_s);
  element_mul(CT->CT[1],CT->CT[1],tempG1);//


  //ct^{(3,1)} - ct^{(3,d)}
  for(int loop=2;loop<=d+1;loop++)
  {
    H(tempZr,tagList[loop-2]);//tag_1 - tag_d
    V(pairing,tempG1,PP,tempZr,xc,d);
    element_pow_zn(tempG1,tempG1,d_s);
    element_mul(CT->CT[loop],CT->CT[loop],tempG1);//
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

int UPDSSE_Decrypt(pairing_t &pairing, SK_S* &SK,CT_S*&CT_, element_t &M)
{

  element_t tempGT1;
  element_t tempGT2;
  element_t tempGT3;
  element_t tempZr;
  element_init_GT(tempGT1, pairing);
  element_init_GT(tempGT2, pairing);
  element_init_GT(tempGT3, pairing);
  element_init_Zr(tempZr, pairing);
  element_t *&tagList=CT_->tagList;
  long i=SK->i;
  long d=CT_->d;

  // 1. 插值计算d+1个系数\omega_i for i in range(0,d)

  // tempList= [t_1, ..., t_d, ... sk^{(4)}]
  element_t *tempList = new element_t[d + 1];
  for (int k = 0; k < d; k++){
    element_init_Zr(tempList[k], pairing);
    H(tempZr,tagList[k]);
    element_set(tempList[k],tempZr);
  }
  element_init_Zr(tempList[d], pairing);


  // omega= [omega_{*}, omega_1, ..., omega_d ]
  int respose;
  element_t **omega = new element_t*[i+1];
  for(int j=0;j<=i;j++)
  {
    omega[j]=new element_t[d+1];
    H(tempZr,SK->SKmain[j][2]);
    element_set(tempList[d],tempZr);

    element_init_Zr(omega[j][0], pairing);
    element_set_si(tempZr,0);
    respose=l(pairing, omega[j][0], tempZr,d, tempList, d);
    if(respose==DIV_ZERO_ERROR){return DECRYPT_FAIL;}
    for (long k = 1; k <= d; k++)
    {
      element_init_Zr(omega[j][k], pairing);
      element_set_si(tempZr,0);
      respose=l(pairing, omega[j][k], tempZr, k-1, tempList, d);
      if(respose==DIV_ZERO_ERROR){return DECRYPT_FAIL;}
    }
  }



  // 2. 计算Z_j  for 0<=j<=i ,并将结果累乘
  element_t*CT=CT_->CT;
  element_t prodZ;
  element_t tempG1_2;
  element_t tempG1_1;
  element_init_GT(prodZ, pairing);
  element_init_G1(tempG1_2, pairing);
  element_init_G1(tempG1_1, pairing);

  element_set1(prodZ);
  for (long j = 0; j <= i; j++)
  {
    //pairing_apply(tempGT1, SK->sk0, CT[1], pairing);
    element_set_si(tempGT1,1);//

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
  element_div(M,M,tempGT1);



  element_clear(tempGT1);
  element_clear(tempGT2);
  element_clear(tempGT3);
  element_clear(prodZ);
  element_clear(tempG1_1);
  element_clear(tempG1_2);
  for(int j=0;j<=i;j++){
    delete[] omega[j];
  }
  delete[] omega;
  return DECRYPT_SUCESS;
}





//测试加密解密能力
int test_UPDSSE(const long d, long pucTimes, int updateTime)
{
  // 1.2 其他参数设置
  // (1) 明文无关参数
  unsigned char* decryptResult=new unsigned char[128];
  PP_S *PP0;
  PP_S *PP;
  SK_S *SK0;
  CT_S*CT;
  element_t t0;
  element_t plain;
  element_t M;
  element_init_Zr(t0, pairing);
  element_init_GT(plain, pairing);
  element_init_GT(M, pairing);
  element_set_si(t0, 0);

  // (2) 安全系数
  const long k = 1024;
  unsigned char w[128] = "hello,world";
  element_from_bytes(M, w);

  // (3) 明文相关参数
  //明文tag
  element_t *TagList = new element_t[d];
  for (int i = 0; i < d; i++)
  {
    element_init_Zr(TagList[i], pairing);
    element_set_si(TagList[i], i + 1);
  }
  // (4) U&&P 参数
  //punture 测试使用的tag
  element_t puncTags[1024];
  for(int loop=0;loop<pucTimes;loop++)
  {
    element_init_Zr(puncTags[loop],pairing);
    element_set_si(puncTags[loop],loop+1024);
  }






  // 2.生成加密公钥PP和私钥SK_0
  printf("KEYGEN START\n");
  UPDSSE_Keygen(pairing, k, d, t0, PP, SK0);



  // 3.使用SK对M进行加密
  printf("ENCRYPT START\n");
  startT=clock();
  UPDSSE_Encrypy(pairing, PP, SK0,M, TagList, CT);
  endT=clock();
  //fprintf(encryT,"%f ",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);


  // 4. puncture
  SK_S *SKi=SK0;
  double averTime=0;
  for (int i = 0; i < pucTimes; i++)
  {
    printf("PUNCTURE \n");
    startT=clock();
    UPDSSE_Puncture(pairing, PP,SKi,puncTags[i]);
    endT=clock();
    averTime+=((double)endT-startT)*1000.0/CLOCKS_PER_SEC;
    //printf("%f \n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  }
  //fprintf(puncT,"%f ",averTime/pucTimes);


  // 5. udate
  SK_S* tempSK=new SK_S(SKi);
  CT_S* tempCT=new CT_S(CT);
  token*token_;
  averTime=0;
  for(int i=0;i<updateTime;i++)
  {
    printf("UPDATE   \n");
    startT=clock();
    UPDSSE_UPDATE_SK(pairing,PP,SKi,token_);
    UPDSSE_UPDATE_CT(pairing,PP,CT,token_);
    endT=clock();
    averTime+=((double)endT-startT)*1000.0/CLOCKS_PER_SEC;
    //printf("%f\n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  }
  //fprintf(updateT,"%f ",averTime/updateTime);


  // 6. decrypt
  printf("DECRYPT  \n");
  startT=clock();
  UPDSSE_Decrypt(pairing, SKi, CT, plain);
  endT=clock();
  //printf("%f\n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  //fprintf(decryT,"%f ",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);



  // check result
  element_to_bytes(decryptResult,plain);
  if (element_cmp(M, plain) == 0)
  {
    printf("***SUCESS DECRYPT***\n");
    printf("PLAINTEXT: \"%s\"\n",decryptResult);
  }
  else{
    printf("***FAIL TO DECRYPT***\n");
  }
  return 0;
}
void calTime()
{
  int max_d=50;
  int max_punc=50;
    for(int puncTimes=0;puncTimes<max_punc;puncTimes++)
    {
      for(int d=0;d<max_d;d++)
      {
       test_UPDSSE(d,puncTimes,1);
       
      }
      printf("%d\n",puncTimes);
      // fprintf(decryT,"\n");
      // fprintf(encryT,"\n");
      // fprintf(puncT,"\n");
      // fprintf(updateT,"\n");
    }
    // fclose(decryT);
    // fclose(encryT);
    // fclose(updateT);
    // fclose(puncT);
}




int isFit(element_t *CTtag,int num1,element_t *searchTag,int num2)
{
  //当且仅当searchTag 属于 CTtag时
  for(int i=0;i<num2;i++)
  {
    int mark=0;
    for(int j=0;j<num1;j++)
    {
      if(!(element_cmp(searchTag[i],CTtag[j])))
      {
        mark=1;
        break;
      }
    }
    if(mark==0){return 0;}
  }
  return 1;
}
//单数据 C/S 交互模型
struct DATA_ENTRY
{
  PP_S*PP;
  CT_S*CT;
};
class DATABASE_S
{
  private:
  int recordNum;
  list<DATA_ENTRY>DATABASE;

  public:
  DATABASE_S()
  {
    this->recordNum=0;
  }
  int UPDSSEDB_ADD(CT_S*CT,PP_S*PP)
  {
    DATA_ENTRY entry;
    entry.CT=CT;
    entry.PP=new PP_S(PP);
    DATABASE.push_front(entry);
    this->recordNum++;
    return 0;
  }
  int UPDSSEDB_DELETE()
  {
    //显示数据库所有项
    int ord=0;
    list<DATA_ENTRY>::iterator it;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      ord+=1;
      printf("%2d. %s\n",ord,it->CT->id);
    }
    //选择一项进行删除
    printf("选择删除项\n");
    int choice=0;
    cin>>choice;
    ord=0;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      if(ord==choice-1)
      {
        DATABASE.erase(it);
        break;
      }
      ord++;
    }

    return 1;
  }

  int DB_UPDATE(token *&token_)
  {
    //更新所有CT
    list<DATA_ENTRY>::iterator it;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      UPDSSE_UPDATE_CT(pairing,it->PP,it->CT,token_);
    }

    //delete token_;
    return 0;
  }
  CT_S* UPDSSEDB_SEARCH(element_t*tagToSearch,int tagNum)
  {
    if(tagNum<=0){return 0;}
    int waitNum=0;
    DATA_ENTRY* waitList=new DATA_ENTRY[recordNum];
    list<DATA_ENTRY>::iterator it;
    system("clear");
    printf("找到以下匹配项:\n");
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      if(isFit(it->CT->tagList,it->CT->d,tagToSearch,tagNum))
      {
        waitList[waitNum]=*it;
        waitNum+=1;
        printf("%2d. %s\n",waitNum,it->CT->id);
      }
    }

    if(waitNum<=0)
    {
      printf("不存在匹配项\n");
      getchar();
      getchar();
      return NULL;
    }
    printf("选择匹配项\n");
    int choice=0;
    cin>>choice;
    if(choice<=0||choice>waitNum)
    {
      return NULL;
    }
    return waitList[choice-1].CT;
  }
};

int serverSimulation()
{
  unsigned char buf[120];
  DATABASE_S DATABASE;
  int maxTagNum=3;
  int k=0;
  PP_S *PP;
  SK_S *SK;

  CT_S *CT;
  element_t t0;
  element_t plain;
  element_t M;
  element_init_Zr(t0, pairing);
  element_init_GT(plain, pairing);
  element_init_GT(M, pairing);
  element_set_si(t0, 0);
  
  printf("密钥生成中.\n");
  UPDSSE_Keygen(pairing,k,maxTagNum,t0,PP,SK);
  printf("生成完成,按任意键继续.\n");
  getchar();system("clear");
  printf("公共参数PP:\n");
  for(int i=0;i<PP->d+3;i++)
  {
    element_printf("%B\n",PP->PP[i]);
  }

  printf("解密私钥SK:\n");
  element_printf("%B\n",SK->sk0);
  element_printf("%B\n",SK->galpha);
  for(int i=0;i<SK->i+1;i++)
  {
    for (int j = 0; j < 3; j++)
    {
      element_printf("%B\n",SK->SKmain[i][j]);
    }
  }
  printf("按任意键继续.\n");
  getchar();system("clear");


  int situ=0;
  while(true)
  {
    printf("客户端操作:\n1.Encrypt : 加密数据并发送至数据库.\n2.Update  : 更新私钥并发送token至数据库\n3.Search  : 请求搜索加密数据库\n4.Delete  : 请求删除数据库中数据\n5.Puncture: 穿刺所持私钥\nother.Exit: 退出\n");
    cin>>situ;
    system("clear");
    switch(situ)
    {
    case 1:
    {
      printf("请依次输入tag,明文及标识\n");
      int tagNum=maxTagNum;
      element_t*tagList=new element_t[tagNum];
      printf("(1) 请输入%d个不同的tag\n",tagNum);
      for(int i=0;i<tagNum;i++)
      {
        element_init_Zr(tagList[i],pairing);
        cin>>buf;
        Hash(tagList[i],buf);
      }
      printf("(2) 请输入待加密内容:\n");
      cin>>buf;
      element_from_bytes(M, buf);
      UPDSSE_Encrypy(pairing,PP,SK,M,tagList,CT);
      
      printf("(3) 请输入内容标识ID:\n");
      CT->id=new char[32];
      cin>>CT->id;
      DATABASE.UPDSSEDB_ADD(CT,PP);

      system("clear");
      printf("加密后记录:\n");
      printf("ID: %s\n",CT->id);
      for(int i=0;i<tagNum;i++)
      {
        element_printf("%B\n",CT->CT[i]);
      }
      printf("已成功保存到数据库\n");
      getchar();
      getchar();
      break;
    }
    case 2:
    {
      token*tok;
      //用户更新自己的密钥
      UPDSSE_UPDATE_SK(pairing,PP,SK,tok);
      //数据库更新所有用户上传的密文
      DATABASE.DB_UPDATE(tok);
      printf("已成功更新\n");
      getchar();
      getchar();
      break;

    }
    case 3:
    {
      int temp,tagNum=0;
      printf("搜索所用tag数为:");
      cin>>tagNum;
      printf("请依次输入搜索使用的tag:\n");
      element_t* searchTag=new element_t[tagNum];
      for(int i=0;i<tagNum;i++)
      {
        cin>>buf;
        element_init_Zr(searchTag[i],pairing);
        Hash(searchTag[i],buf);
        //element_printf("%B\n", searchTag[i]);
      }
      CT=DATABASE.UPDSSEDB_SEARCH(searchTag,tagNum);
      if(CT==NULL)
      {
        break;
      }

      printf("尝试使用密钥解密:");
      int res=UPDSSE_Decrypt(pairing,SK,CT,M);
      if(res==DECRYPT_FAIL)
      {
        printf("所持有的密钥无法解密该密文\n");
      }
      else{
        printf("尝试解密结果为:\n");
        element_to_bytes(buf,M);
        printf("PLAINTEXT: \"%s\"\n",buf);
      }
      getchar();
      getchar();
      break;
    }
    case 4:
    {
      DATABASE.UPDSSEDB_DELETE();
      break;
    }
    case 5:
    {
      int tagNum=0;
      printf("穿刺所用tag数为:");
      cin>>tagNum;
      printf("请依次输入搜索使用的tag:\n");
      element_t* puncTag=new element_t[tagNum];
      for(int i=0;i<tagNum;i++)
      {
        cin>>buf;
        element_init_Zr(puncTag[i],pairing);
        Hash(puncTag[i],buf);
      }
      for(int i=0;i<tagNum;i++)
      {
        UPDSSE_Puncture(pairing,PP,SK,puncTag[i]);
      }
      printf("密钥穿刺完成");


    }
    default:
    {
      char exit;
      printf("确定退出?(y/n)\n");
      getchar();
      exit=getchar();
      if(exit=='y')
      {
        return 1;
      }
      
      break;
    }
    }
        system("clear");
  }
  return 0;
}


int main(int argc, char const *argv[])
{
  INIT();
  //test_UPDSSE(4,4,4);
  serverSimulation();
  return 0;
}

