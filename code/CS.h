/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-21 21:46:28
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
#define SERV_PORT 9988
#define SERV_IP "127.0.0.1"
#define MAX_KEYWORD_LEN 32
#define MAX_INDICE_LEN 32

#define COMMAND_TYPE char
#define COMMAND_BYTE_LENGTH 1
#define COMMAND_SETUP 0x11
#define COMMAND_SEARCH 0x12
#define COMMAND_ADD 0x13
#define COMMAND_DEL 0x14
#define COMMAND_UPDATEKEY 0x15
const char COMMAND_SETUP_CHAR = COMMAND_SETUP;
const char COMMAND_SEARCH_CHAR = COMMAND_SEARCH;
const char COMMAND_ADD_CHAR = COMMAND_ADD;
const char COMMAND_DEL_CHAR = COMMAND_DEL;
const char COMMAND_UPDATEKEY_CHAR = COMMAND_UPDATEKEY;

void INIT();
int server(void);
int client(void);
int printClientMenu();
