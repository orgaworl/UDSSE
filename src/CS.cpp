/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-21 21:46:36
 */
#include "../include/CS.h"

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

    pairing_t pairing;
    INIT(pairing);

    // Setup
    // len = read(cfd, buf, sizeof(buf));
    // if(len==COMMAND_BYTE_LENGTH&&*(COMMAND_TYPE*)buf==COMMAND_SETUP)
    // {
    //     UDSSE_Setup_Server(pairing,sfd);
    // }
    // UDSSE_Setup_Server(pairing,sfd);

    COMMAND_TYPE command;
    while (1)
    {
        /*读取客户端发送数据*/
        len = read(cfd, &command, COMMAND_BYTE_LENGTH);
        printf("command %d :", (int)command);
        /*处理客户端数据*/
        if (len == COMMAND_BYTE_LENGTH)
        {
            // 传入命令数据
            switch (command)
            {
            case COMMAND_SETUP_CHAR:
                printf("setup\n ");
                sleep(4);
                UDSSE_Setup_Server(pairing,sfd);
                break;
            case COMMAND_SEARCH_CHAR:
            printf("search\n ");
                UDSSE_Search_Server(pairing, sfd);
                break;

            case COMMAND_ADD_CHAR:
            printf("add\n ");
                UDSSE_Update_Server(pairing, sfd);
                break;

            case COMMAND_DEL_CHAR:
            printf("del\n ");
                UDSSE_Update_Server(pairing, sfd);
                break;

            case COMMAND_UPDATEKEY_CHAR:
                UDSSE_UpdateKey_Server(pairing,sfd);
                break;
            default:
                printf("command error\n");
                break;
            }
        }
    }

    /*关闭链接*/
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

    // 3. Setup
    // printf("U r creating a new database stored in the server.\n\
    //             All settings will be cleared and set to default values.");
    printf("Init with server. \n");

    // 4. UDSSE
    while (1)
    {
        system("clear");
        printClientMenu();
        choice = 0;
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
        // Setup
            send(sfd, &COMMAND_SETUP_CHAR, COMMAND_BYTE_LENGTH, 0);
            UDSSE_Setup_Client(pairing, sfd, lambda, d);
            break;
        case 2:
            // ADD
            scanf("%s  %s", tempKeyWord, tempIndice);
            send(sfd, &COMMAND_ADD_CHAR, COMMAND_BYTE_LENGTH, 0);
            UDSSE_Update_Client(pairing, sfd, OP_ADD, tempKeyWord, tempIndice);
            break;
        case 3:
            // DEL
            scanf("%s  %s", tempKeyWord, tempIndice);
            send(sfd, &COMMAND_DEL_CHAR, COMMAND_BYTE_LENGTH, 0);
            UDSSE_Update_Client(pairing, sfd, OP_DEL, tempKeyWord, tempIndice);
            break;
        case 4:
            // Search
            scanf("%s", tempKeyWord);
            send(sfd, &COMMAND_SEARCH_CHAR, COMMAND_BYTE_LENGTH, 0);
            UDSSE_Search_Client(pairing, sfd, tempKeyWord);
            break;
        case 5:
            //
            // scanf("%s", tempKeyWord);
            // send(sfd, "SEARCH", 5, 0);
            // UDSSE_Search_Client(pairing, sfd, tempKeyWord);
            break;

        case 9:
            goto END;
            break;
        default:
            printf("\n Not supported command,try again plz.\n");
            getchar();
            getchar();
            break;
        }
    }
END:
    /*关闭链接*/
    close(sfd);
    return 0;
}
int printClientMenu(void)
{
    printf("\
    client menu:\n\
    1:Setup your database in the server.\n\
    2:Add entries to your database in the server.\n\
    3:Delete  entries to your database in the server.\n\
    4.Serch on you database in the server.\n\
    9:Exit.\n\
    Please input your choice(1/2/3/4/9):\n\
    ");
    return 0;
}

// /*从标准输入获取数据*/
// fgets(buf, sizeof(buf), stdin);
// /*将数据写给服务器*/
// write(sfd, buf, strlen(buf));
// /*从服务器读回转换后数据*/
// len = read(sfd, buf, sizeof(buf));
// /*写至标准输出*/
// write(STDOUT_FILENO, buf, len);