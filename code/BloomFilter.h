/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:00:41
 */
//#include<stdio.h>
#pragma once
#include "/usr/local/include/pbc/pbc.h"
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <bitset>
using namespace std;

#define BF_CHECK_TRUE 1
#define BF_CHECK_FALSE 0
#define b_MAX_VALUE 1024*4

#define H_main int *
#define B_main bitset *

class H_S
{
public:
    int h;
    //H_main main;

    H_S(int h)
    {
        this->h = h;
        //main = NULL;
    }
    H_S(H_S &copy)
    {
        this->h = copy.h;
        // this->main = new int[h];
        // for (int i = 0; i < h; i++)
        //     this->main[i] = copy.main[i];
    }
    ~H_S()
    {
        // if (main != NULL)
        //     delete[] main;
    }
};

class B_S
{
public:
    //int b;
    std::bitset<b_MAX_VALUE> *main;
    B_S()
    {
        //b = 0;
        main = NULL;
    }
    B_S(B_S &copy)
    {
        //b = copy.b;
        main = new bitset<b_MAX_VALUE>(copy.main);
    }
    B_S(bitset<b_MAX_VALUE>copy)
    {
        main = new bitset<b_MAX_VALUE>(copy);
    }
    ~B_S()
    {
        if (main != NULL)
            delete[] main;
    }
};

int Hash2Int(element_t &x, int HashChoice);
int accessB(B_S *&B, uint hashValue, int val = -1);
int BF_Gen(int b, int h, H_S *&H, B_S *&B);
int BF_Update(H_S *&H, B_S *&B, element_t &x);
int BF_Check(H_S *&H, B_S *&B, element_t &x);
int BF_Free(H_S *&H, B_S *&B);
