/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-21 21:46:36
 */
#include "../../include/benchMark.h"

// 1.1 初始化双线性对

void INIT(pairing_t &pairing)
{
    char param[1024];
    FILE *file = fopen("../param/a.param", "r");
    size_t count = fread(param, 1, 1024, file);
    fclose(file);
    pairing_init_set_buf(pairing, param, count);
}

int server(void)
{
    // 1. Web setting
    int sfd, cfd;
    int len, i;
    char buf[BUFSIZ], clie_IP[BUFSIZ];

    struct sockaddr_in serv_addr, clie_addr;
    socklen_t clie_addr_len;
    sfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&serv_addr, sizeof(serv_addr));          // 将整个结构体清零
    serv_addr.sin_family = AF_INET;                // 选择协议族为IPv4
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 监听本地所有IP地址
    serv_addr.sin_port = htons(SERV_PORT);         // 绑定端口号

    bind(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    listen(sfd, 64); // 同一时刻允许向服务器发起链接请求的数量
    printf("wait for client connect ...\n");

    /*获取客户端地址结构大小*/
    clie_addr_len = sizeof(clie_addr_len);
    /*参数1是sfd; 参2传出参数, 参3传入传入参数, 全部是client端的参数*/
    cfd = accept(sfd, (struct sockaddr *)&clie_addr, &clie_addr_len); /*监听客户端链接, 会阻塞*/
    printf("client IP:%s\tport:%d\n",
           inet_ntop(AF_INET, &clie_addr.sin_addr.s_addr, clie_IP, sizeof(clie_IP)),
           ntohs(clie_addr.sin_port));

    // 2. Cipher setting
    pairing_t pairing;
    INIT(pairing);
    COMMAND_TYPE command;
    int end = 0;
    while (!end)
    {
        /*读取客户端发送数据*/
        command = 0;
        memset(buf, 0, TRANS_BUF_SIZE);
        len = read(cfd, &command, COMMAND_BYTE_LENGTH); // 读取指令
        if (command == 0 || len == 0)
            continue;
        len = read(cfd, buf, TRANS_BUF_SIZE); // 读取数据
        printf("command %d :", (int)command);
        /*处理客户端数据*/

        // 传入命令数据
        switch (command)
        {
        case COMMAND_SETUP_CHAR:
            printf("setup\n ");
            UDSSE_Setup_Server(pairing, buf);
            break;
        case COMMAND_SEARCH_CHAR:
            printf("search\n ");
            UDSSE_Search_Server(pairing, buf);
            break;

        case COMMAND_ADD_CHAR:
            printf("add\n ");
            UDSSE_Update_Server(pairing, buf);
            break;


        case COMMAND_UPDATEKEY_CHAR:
            printf("up key\n ");
            UDSSE_UpdateKey_Server(pairing, buf);
            break;

        case COMMAND_END_CHAR:
            end = 1;
            break;
        default:
            printf("command error\n");
            break;
        }
    }
    close(sfd);
    close(cfd);
    return 0;
}

int client(void)
{
    // 1. Web para set
    int sfd, len;
    struct sockaddr_in serv_addr;
    char buf[BUFSIZ];
    /*创建一个socket 指定IPv4 TCP*/
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    /*初始化一个地址结构:*/
    bzero(&serv_addr, sizeof(serv_addr));                    // 清零
    serv_addr.sin_family = AF_INET;                          // IPv4协议族
    inet_pton(AF_INET, SERV_IP, &serv_addr.sin_addr.s_addr); // 指定IP 字符串类型转换为网络字节序 参3:传出参数
    serv_addr.sin_port = htons(SERV_PORT);                   // 指定端口 本地转网络字节序
    /*根据地址结构链接指定服务器进程*/
    connect(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("Connect Server Successful.\n");
    getchar();

    // 2. Cipher para set
    pairing_t pairing;
    INIT(pairing);
    int lambda = 1024;
    int d = 1;

    char tempKeyWord[MAX_KEYWORD_LEN];
    char tempIndice[MAX_INDICE_LEN];
    int choice;
    int end = 0;
    while (!end)
    {
        system("clear");
        choice = 0;
        memset(buf, 0, TRANS_BUF_SIZE);
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            // Setup
            UDSSE_Setup_Client(pairing, buf, lambda);
            send(sfd, &COMMAND_SETUP_CHAR, COMMAND_BYTE_LENGTH, 0); // 发送指令
            send(sfd, buf, TRANS_BUF_SIZE, 0);                      // 发送数据
            break;
        case 2:
            // ADD
            printf("keywords:\n");
            scanf("%s", tempKeyWord);
            printf("plain:\n");
            scanf("%s", tempIndice);
            UDSSE_Update_Client(pairing, buf, OP_ADD, tempKeyWord, tempIndice);
            send(sfd, &COMMAND_ADD_CHAR, COMMAND_BYTE_LENGTH, 0);
            send(sfd, buf, TRANS_BUF_SIZE, 0);
            break;
        case 3:
            // DEL
            printf("keywords:\n");
            scanf("%s", tempKeyWord);
            printf("plain:\n");
            scanf("%s", tempIndice);
            UDSSE_Update_Client(pairing, buf, OP_DEL, tempKeyWord, tempIndice);
            // 本地处理，无需发送数据
            break;
        case 4:
            // Search
            printf("keywords:\n");
            scanf("%s", tempKeyWord);
            UDSSE_Search_Client(pairing, buf, tempKeyWord);
            send(sfd, &COMMAND_SEARCH_CHAR, COMMAND_BYTE_LENGTH, 0);
            send(sfd, buf, TRANS_BUF_SIZE, 0);
            break;
        case 5:
            printf("keywords:\n");
            scanf("%s", tempKeyWord);
            UDSSE_UpdateKey_Client(pairing, buf, tempKeyWord);
            send(sfd, &COMMAND_UPDATEKEY_CHAR, COMMAND_BYTE_LENGTH, 0);
            send(sfd, buf, TRANS_BUF_SIZE, 0);
            break;
        case 9:
            send(sfd, &COMMAND_END_CHAR, COMMAND_BYTE_LENGTH, 0);
            end = 1;
            break;
        default:
            printf("\n Not supported command,try again plz.\n");
            getchar();
            break;
        }
        getchar();
    }
    /*关闭链接*/
    close(sfd);
    return 0;
}
