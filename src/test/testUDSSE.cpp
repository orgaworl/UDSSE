/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-06 18:23:27
 */
#pragma once
#include <stdio.h>
#include <unistd.h>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdlib.h>
#include <map>
#include <vector>

#include "/usr/local/include/pbc/pbc.h"
#include "../../include/CS.h"
int testUDSSE()
{
    pairing_t pairing;
    INIT(pairing);
    int lambda = 1024;
    int d = 1;

    int mark = 0;

    UDSSE_Setup_Client(pairing, 0, lambda);
    UDSSE_Setup_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key1234567", "ABCDEF");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key1234567", "123456");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key1234567", "987654321");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key1234567", "test");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_DEL, "key1234567", "987654321");

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key09876", "A1B2C3");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_Update_Client(pairing, 0, OP_ADD, "key09876", "12341");
    UDSSE_Update_Server(pairing, 0);

    UDSSE_UpdateKey_Client(pairing, 0, "key1234567");
    UDSSE_UpdateKey_Server(pairing, 0);

    UDSSE_UpdateKey_Client(pairing, 0, "key1234567");
    UDSSE_UpdateKey_Server(pairing, 0);

    mark = UDSSE_Search_Client(pairing, 0, "key1234567");
    if (mark == UDSSE_Search_Client_Sucess)
    {
        UDSSE_Search_Server(pairing, 0);
    }

    mark = UDSSE_Search_Client(pairing, 0, "key09876");
    if (mark == UDSSE_Search_Client_Sucess)
    {
        UDSSE_Search_Server(pairing, 0);
    }

    mark = UDSSE_Search_Client(pairing, 0, "testf");
    if (mark == UDSSE_Search_Client_Sucess)
    {
        UDSSE_Search_Server(pairing, 0);
    }
}
const int MAXLEN = TRANS_BUF_SIZE * 20480;
char gbuf[MAXLEN];
int benchMark01(int len1=8,int len2=8)
{
    pairing_t pairing;
    INIT(pairing);
    int lambda = 1024;
    int d = 1;

    int mark = 0;

    UDSSE_Setup_Client(pairing, gbuf, lambda);
    UDSSE_Setup_Server(pairing, gbuf);
    // add
    char buf[128];
    for (int i = 0; i < 128; i++)
    {
        buf[i] = 'A';
    }
    string ind(buf,len1);
    string key(buf,len2);
    int loop = 80;
    clock_t start, end;
    clock_t add_time[loop];
    clock_t upk_time[loop];
    clock_t search_time[loop];
    for (int i = 0; i < loop; i++)
    {
        // add
        ind[i / 25] = (i % 25) + 65 + 1;
        add_time[i] = 0;
        memset(gbuf, 0, MAXLEN);
        start = clock();
        if (UDSSE_Update_Client_Sucess == UDSSE_Update_Client(pairing, gbuf, OP_ADD, key, ind))
        {
            UDSSE_Update_Server(pairing, gbuf);
            add_time[i] = clock() - start;
        }

        // up key
        memset(gbuf, 0, MAXLEN);
        upk_time[i] = 0;
        start = clock();
        if (UDSSE_UpdateKey_Client_Sucess == UDSSE_UpdateKey_Client(pairing, gbuf, key))
        {
            UDSSE_UpdateKey_Server(pairing, gbuf);
            upk_time[i] = clock() - start;
        }

        // search
        memset(gbuf, 0, MAXLEN);
        search_time[i] = 0;
        start = clock();
        if (UDSSE_Search_Client_Sucess == UDSSE_Search_Client(pairing, gbuf,key))
        {
            UDSSE_Search_Server(pairing, gbuf);
            search_time[i] = clock() - start;
        }
    }

    for (int i = 0; i < loop; i++)
    {
        printf("%f ", (double)(add_time[i]) / CLOCKS_PER_SEC);
        printf("%f ", (double)(upk_time[i]) / CLOCKS_PER_SEC);
        printf("%f ", (double)(search_time[i]) / CLOCKS_PER_SEC);
        if (i == 0)
        {
            printf("0 0 0 ");
        }
        else
        {
            printf("%f ", (double)(add_time[i] - add_time[i - 1]) / CLOCKS_PER_SEC);
            printf("%f ", (double)(upk_time[i] - upk_time[i - 1]) / CLOCKS_PER_SEC);
            printf("%f ", (double)(search_time[i] - search_time[i - 1]) / CLOCKS_PER_SEC);
        }
        printf("\n");
    }
}
int benchMark02()
{
    pairing_t pairing;
    INIT(pairing);
    int lambda = 1024;
    int d = 1;
    int mark = 0;

    UDSSE_Setup_Client(pairing, gbuf, lambda);
    UDSSE_Setup_Server(pairing, gbuf);

    // add
    char buf[128];
    for (int i = 0; i < 128; i++)
    {
        buf[i] = 'A';
    }

    int loop = 32;
    clock_t start, end;
    clock_t add_time[loop];
    clock_t upk_time[loop];
    clock_t search_time[loop];
    string ind(buf, 8);
    for (int i = 1; i < loop; i += 1)
    {
        // add
        buf[i / 25] = (i % 25) + 65 + 1;
        
        string key(buf,i);
        add_time[i] = 0;
        memset(gbuf, 0, MAXLEN);
        start = clock();
        if (UDSSE_Update_Client_Sucess == UDSSE_Update_Client(pairing, gbuf, OP_ADD, key, ind))
        {
            UDSSE_Update_Server(pairing, gbuf);
            add_time[i] = clock() - start;
        }
        else
        {
            return 0;
        }

        // up key
        memset(gbuf, 0, MAXLEN);
        upk_time[i] = 0;
        start = clock();
        if (UDSSE_UpdateKey_Client_Sucess == UDSSE_UpdateKey_Client(pairing, gbuf, key))
        {
            UDSSE_UpdateKey_Server(pairing, gbuf);
            upk_time[i] = clock() - start;
        }
        else
        {
            return 0;
        }

        // search
        memset(gbuf, 0, MAXLEN);
        search_time[i] = 0;
        start = clock();
        if (UDSSE_Search_Client_Sucess == UDSSE_Search_Client(pairing, gbuf, key))
        {
            UDSSE_Search_Server(pairing, gbuf);
            search_time[i] = clock() - start;
        }
        else
        {
            return 0;
        }
        printf("%d ", i);
        printf("%f ", (double)(add_time[i]) / CLOCKS_PER_SEC);
        printf("%f ", (double)(upk_time[i]) / CLOCKS_PER_SEC);
        printf("%f ", (double)(search_time[i]) / CLOCKS_PER_SEC);
        printf("\n");
    }
}
int main()
{
    // benchMark01();

    benchMark02();

    return 0;
}