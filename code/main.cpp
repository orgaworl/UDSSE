#include <stdio.h>
#include <string.h>
#include <list>
#include <ctime>
#include <iostream>
#include "/usr/local/include/pbc/pbc.h"
#include"UDSSE.h"
using namespace std;

// FILE *poi = fopen("./output.txt", "w+");
//  FILE *encryT = fopen("./time/encryT.txt", "w+");
//  FILE *puncT = fopen("./time/puncT.txt", "w+");
//  FILE *updateT = fopen("./time/updateT.txt", "w+");
//  FILE *decryT = fopen("./time/decryT.txt", "w+");

int base = 10;
time_t startT;
time_t endT;

// 1.1 初始化双线性对
pairing_t pairing;
void INIT()
{
  char param[1024];
  FILE *file = fopen("../param/a.param", "r");
  size_t count = fread(param, 1, 1024, file);
  fclose(file);
  pairing_init_set_buf(pairing, param, count);
}

// 测试加密解密能力
int test_UPE(const long d, long pucTimes, int updateTime)
{
  // 1.2 其他参数设置
  // (1) 明文无关参数
  unsigned char *decryptResult = new unsigned char[128];
  PP_S *PP0;
  PP_S *PP;
  SK_S *SK0;
  CT_S *CT;
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
  // 明文tag
  element_t *TagList = new element_t[d];
  for (int i = 0; i < d; i++)
  {
    element_init_Zr(TagList[i], pairing);
    element_set_si(TagList[i], i + 1);
  }
  // (4) U&&P 参数
  // punture 测试使用的tag
  element_t puncTags[1024];
  for (int loop = 0; loop < pucTimes; loop++)
  {
    element_init_Zr(puncTags[loop], pairing);
    element_set_si(puncTags[loop], loop + 1024);
  }

  // 2.生成加密公钥PP和私钥SK_0
  printf("KEYGEN START\n");
  UPE_Keygen(pairing, k, d, t0, PP, SK0);

  // 3.使用SK对M进行加密
  printf("ENCRYPT START\n");
  startT = clock();
  UPE_Encrypy(pairing, PP, SK0, M, TagList, CT);
  endT = clock();
  // fprintf(encryT,"%f ",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);

  // 4. puncture
  SK_S *SKi = SK0;
  double averTime = 0;
  for (int i = 0; i < pucTimes; i++)
  {
    printf("PUNCTURE \n");
    startT = clock();
    UPE_Puncture(pairing, PP, SKi, puncTags[i]);
    endT = clock();
    averTime += ((double)endT - startT) * 1000.0 / CLOCKS_PER_SEC;
    // printf("%f \n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  }
  // fprintf(puncT,"%f ",averTime/pucTimes);

  // 5. udate
  SK_S *tempSK = new SK_S(SKi, pairing);
  CT_S *tempCT = new CT_S(CT, pairing);
  token *token_;
  averTime = 0;
  for (int i = 0; i < updateTime; i++)
  {
    printf("UPDATE   \n");
    startT = clock();
    UPE_UPDATE_SK(pairing, PP, SKi, token_);
    UPE_UPDATE_CT(pairing, PP, CT, token_);
    endT = clock();
    averTime += ((double)endT - startT) * 1000.0 / CLOCKS_PER_SEC;
    // printf("%f\n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  }
  // fprintf(updateT,"%f ",averTime/updateTime);

  // 6. decrypt
  printf("DECRYPT  \n");
  startT = clock();
  UPE_Decrypt(pairing, SKi, CT, plain);
  endT = clock();
  // printf("%f\n",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);
  // fprintf(decryT,"%f ",((double)endT-startT)*1000.0/CLOCKS_PER_SEC);

  // check result
  element_to_bytes(decryptResult, plain);
  if (element_cmp(M, plain) == 0)
  {
    printf("***SUCESS DECRYPT***\n");
    printf("PLAINTEXT: \"%s\"\n", decryptResult);
  }
  else
  {
    printf("***FAIL TO DECRYPT***\n");
  }
  return 0;
}
void calTime()
{
  int max_d = 50;
  int max_punc = 50;
  for (int puncTimes = 0; puncTimes < max_punc; puncTimes++)
  {
    for (int d = 0; d < max_d; d++)
    {
      test_UPE(d, puncTimes, 1);
    }
    printf("%d\n", puncTimes);
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

int isFit(element_t *CTtag, int num1, element_t *searchTag, int num2)
{
  // 当且仅当searchTag 属于 CTtag时
  for (int i = 0; i < num2; i++)
  {
    int mark = 0;
    for (int j = 0; j < num1; j++)
    {
      if (!(element_cmp(searchTag[i], CTtag[j])))
      {
        mark = 1;
        break;
      }
    }
    if (mark == 0)
    {
      return 0;
    }
  }
  return 1;
}
// 单数据 C/S 交互模型
struct DATA_ENTRY
{
  PP_S *PP;
  CT_S *CT;
};
class DATABASE_S
{
private:
  int recordNum;
  list<DATA_ENTRY> DATABASE;

public:
  DATABASE_S()
  {
    this->recordNum = 0;
  }
  int UPEDB_ADD(CT_S *CT, PP_S *PP)
  {
    DATA_ENTRY entry;
    entry.CT = CT;
    entry.PP = new PP_S(PP, pairing);
    DATABASE.push_front(entry);
    this->recordNum++;
    return 0;
  }
  int UPEDB_DELETE()
  {
    // 显示数据库所有项
    int ord = 0;
    list<DATA_ENTRY>::iterator it;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      ord += 1;
      printf("%2d. %s\n", ord, it->CT->id);
    }
    // 选择一项进行删除
    printf("选择删除项\n");
    int choice = 0;
    cin >> choice;
    ord = 0;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      if (ord == choice - 1)
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
    // 更新所有CT
    list<DATA_ENTRY>::iterator it;
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      UPE_UPDATE_CT(pairing, it->PP, it->CT, token_);
    }

    // delete token_;
    return 0;
  }
  CT_S *UPEDB_SEARCH(element_t *tagToSearch, int tagNum)
  {
    if (tagNum <= 0)
    {
      return 0;
    }
    int waitNum = 0;
    DATA_ENTRY *waitList = new DATA_ENTRY[recordNum];
    list<DATA_ENTRY>::iterator it;
    system("clear");
    printf("找到以下匹配项:\n");
    for (it = DATABASE.begin(); it != DATABASE.end(); it++)
    {
      if (isFit(it->CT->tagList, it->CT->d, tagToSearch, tagNum))
      {
        waitList[waitNum] = *it;
        waitNum += 1;
        printf("%2d. %s\n", waitNum, it->CT->id);
      }
    }

    if (waitNum <= 0)
    {
      printf("不存在匹配项\n");
      getchar();
      getchar();
      return NULL;
    }
    printf("选择匹配项\n");
    int choice = 0;
    cin >> choice;
    if (choice <= 0 || choice > waitNum)
    {
      return NULL;
    }
    return waitList[choice - 1].CT;
  }
};


int serverSimulation()
{
  unsigned char buf[120];
  DATABASE_S DATABASE;
  int maxTagNum = 3;
  int k = 0;
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
  UPE_Keygen(pairing, k, maxTagNum, t0, PP, SK);
  printf("生成完成,按任意键继续.\n");
  getchar();
  system("clear");
  printf("公共参数PP:\n");
  for (int i = 0; i < PP->d + 3; i++)
  {
    element_printf("%B\n", PP->PP[i]);
  }

  printf("解密私钥SK:\n");
  element_printf("%B\n", SK->sk0);
  element_printf("%B\n", SK->galpha);
  for (int i = 0; i < SK->i + 1; i++)
  {
    for (int j = 0; j < 3; j++)
    {
      element_printf("%B\n", SK->SKmain[i][j]);
    }
  }
  printf("按任意键继续.\n");
  getchar();
  system("clear");

  int situ = 0;
  while (true)
  {
    printf("客户端操作:\n1.Encrypt : 加密数据并发送至数据库.\n2.Update  : 更新私钥并发送token至数据库\n3.Search  : 请求搜索加密数据库\n4.Delete  : 请求删除数据库中数据\n5.Puncture: 穿刺所持私钥\nother.Exit: 退出\n");
    cin >> situ;
    system("clear");
    switch (situ)
    {
    case 1:
    {
      printf("请依次输入tag,明文及标识\n");
      int tagNum = maxTagNum;
      element_t *tagList = new element_t[tagNum];
      printf("(1) 请输入%d个不同的tag\n", tagNum);
      for (int i = 0; i < tagNum; i++)
      {
        element_init_Zr(tagList[i], pairing);
        cin >> buf;
        Hash(tagList[i], buf);
      }
      printf("(2) 请输入待加密内容:\n");
      cin >> buf;
      element_from_bytes(M, buf);
      UPE_Encrypy(pairing, PP, SK, M, tagList, CT);

      printf("(3) 请输入内容标识ID:\n");
      CT->id = new char[32];
      cin >> CT->id;
      DATABASE.UPEDB_ADD(CT, PP);

      system("clear");
      printf("加密后记录:\n");
      printf("ID: %s\n", CT->id);
      for (int i = 0; i < tagNum; i++)
      {
        element_printf("%B\n", CT->CT[i]);
      }
      printf("已成功保存到数据库\n");
      getchar();
      getchar();
      break;
    }
    case 2:
    {
      token *tok;
      // 用户更新自己的密钥
      UPE_UPDATE_SK(pairing, PP, SK, tok);
      // 数据库更新所有用户上传的密文
      DATABASE.DB_UPDATE(tok);
      printf("已成功更新\n");
      getchar();
      getchar();
      break;
    }
    case 3:
    {
      int temp, tagNum = 0;
      printf("搜索所用tag数为:");
      cin >> tagNum;
      printf("请依次输入搜索使用的tag:\n");
      element_t *searchTag = new element_t[tagNum];
      for (int i = 0; i < tagNum; i++)
      {
        cin >> buf;
        element_init_Zr(searchTag[i], pairing);
        Hash(searchTag[i], buf);
        // element_printf("%B\n", searchTag[i]);
      }
      CT = DATABASE.UPEDB_SEARCH(searchTag, tagNum);
      if (CT == NULL)
      {
        break;
      }

      printf("尝试使用密钥解密:");
      int res = UPE_Decrypt(pairing, SK, CT, M);
      if (res == DECRYPT_FAIL)
      {
        printf("所持有的密钥无法解密该密文\n");
      }
      else
      {
        printf("尝试解密结果为:\n");
        element_to_bytes(buf, M);
        printf("PLAINTEXT: \"%s\"\n", buf);
      }
      getchar();
      getchar();
      break;
    }
    case 4:
    {
      DATABASE.UPEDB_DELETE();
      break;
    }
    case 5:
    {
      int tagNum = 0;
      printf("穿刺所用tag数为:");
      cin >> tagNum;
      printf("请依次输入搜索使用的tag:\n");
      element_t *puncTag = new element_t[tagNum];
      for (int i = 0; i < tagNum; i++)
      {
        cin >> buf;
        element_init_Zr(puncTag[i], pairing);
        Hash(puncTag[i], buf);
      }
      for (int i = 0; i < tagNum; i++)
      {
        UPE_Puncture(pairing, PP, SK, puncTag[i]);
      }
      printf("密钥穿刺完成");
    }
    default:
    {
      char exit;
      printf("确定退出?(y/n)\n");
      getchar();
      exit = getchar();
      if (exit == 'y')
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
  // test_UPE(4,4,4);
  serverSimulation();
  return 0;
}
