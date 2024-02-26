/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-21 21:46:28
 */
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
#include "UDSSE.h"
#define SERV_PORT 9988
#define SERV_IP "127.0.0.1"

map<string,element_t> MSK;

int server(void);
int client(void);
int printClientMenu();
