/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-06 18:23:27
 */
#pragma once
#include <stdio.h>
#include <unistd.h>
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
#include "UDSSE.h"
void INIT(pairing_t &pairing)
{
    char param[1024];
    FILE *file = fopen("../param/a.param", "r");
    size_t count = fread(param, 1, 1024, file);
    fclose(file);
    pairing_init_set_buf(pairing, param, count);
}

int main()
{
    pairing_t pairing;
    INIT(pairing);
    int lambda = 1024;
    int d = 1;

    int mark = 0;


    UDSSE_Setup_Client(pairing, 0, lambda, d);
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
    // UDSSE_Update_Server(pairing, 0);


    UDSSE_Update_Client(pairing, 0, OP_ADD, "key09876", "A1B2C3");
    UDSSE_Update_Server(pairing, 0);


    UDSSE_Update_Client(pairing, 0, OP_ADD, "key09876", "12341");
    UDSSE_Update_Server(pairing, 0);


    printf("search\n");
    mark = UDSSE_Search_Client(pairing, 0, "key1234567");
    if (mark == UDSSE_Search_Client_Sucess)
    {
        UDSSE_Search_Server(pairing, 0);
    }

    // printf("search\n");
    // mark = UDSSE_Search_Client(pairing, 0, "key09876");
    // if (mark == UDSSE_Search_Client_Sucess)
    // {
    //     UDSSE_Search_Server(pairing, 0);
    // }



    // printf("search\n");
    // mark = UDSSE_Search_Client(pairing, 0, "testf");
    // if (mark == UDSSE_Search_Client_Sucess)
    // {
    //     UDSSE_Search_Server(pairing, 0);
    // }

    return 0;
}