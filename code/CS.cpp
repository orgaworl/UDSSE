/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-21 21:46:36
 */
#include "CS.h"

int server(void)
{
    int sfd, cfd;
    int len, i;
    char buf[BUFSIZ], clie_IP[BUFSIZ];

    struct sockaddr_in serv_addr, clie_addr;
    socklen_t clie_addr_len;

    /*创建一个socket 指定IPv4协议族 TCP协议*/
    sfd = socket(AF_INET, SOCK_STREAM, 0);

    /*初始化一个地址结构 man 7 ip 查看对应信息*/
    bzero(&serv_addr, sizeof(serv_addr));          // 将整个结构体清零
    serv_addr.sin_family = AF_INET;                // 选择协议族为IPv4
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 监听本地所有IP地址
    serv_addr.sin_port = htons(SERV_PORT);         // 绑定端口号

    /*绑定服务器地址结构*/
    bind(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    /*设定链接上限,注意此处不阻塞*/
    listen(sfd, 64); // 同一时刻允许向服务器发起链接请求的数量

    printf("wait for client connect ...\n");

    /*获取客户端地址结构大小*/
    clie_addr_len = sizeof(clie_addr_len);
    /*参数1是sfd; 参2传出参数, 参3传入传入参数, 全部是client端的参数*/
    cfd = accept(sfd, (struct sockaddr *)&clie_addr, &clie_addr_len); /*监听客户端链接, 会阻塞*/

    printf("client IP:%s\tport:%d\n",
           inet_ntop(AF_INET, &clie_addr.sin_addr.s_addr, clie_IP, sizeof(clie_IP)),
           ntohs(clie_addr.sin_port));

    while (1)
    {
        /*读取客户端发送数据*/
        len = read(cfd, buf, sizeof(buf));
        write(STDOUT_FILENO, buf, len);

        /*处理客户端数据*/
        for (i = 0; i < len; i++)
            buf[i] = toupper(buf[i]);

        /*处理完数据回写给客户端*/
        write(cfd, buf, len);
    }

    /*关闭链接*/
    close(sfd);
    close(cfd);

    return 0;
}

struct mapValPair
{
    element_t msk;
    int i;
    vector<element_t> D;
};
map<string,mapValPair> MAP;
element_t K;


int client(void)
{
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

    int lambda = 1024;
    int d = 1024;
    while (1)
    {
        system("clear");
        printClientMenu();
        int choice = 0;
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            // Setup
            printf("U r creating a new database stored in the server.\n\
                All settings will be cleared and set to default values.");
            UDSSE_Setup(sfd, lambda, d);
            break;
        case 2:
            // ADD

            UDSSE_Update(sfd, OP_ADD, omega, ind);

            break;
        case 3:
            // DEL
            UDSSE_Update(sfd, OP_DEL, omega, ind);

            break;
        case 4:
            // Search
            UDSSE_Search(sfd, omega, i);
            break;
        case 9:
            goto END;
            break;
        default:
            printf("\n\
        Not supported command,try again plz.\n");
            getchar();
            getchar();
            break;
        }

        // /*从标准输入获取数据*/
        // fgets(buf, sizeof(buf), stdin);
        // /*将数据写给服务器*/
        // write(sfd, buf, strlen(buf));
        // /*从服务器读回转换后数据*/
        // len = read(sfd, buf, sizeof(buf));
        // /*写至标准输出*/
        // write(STDOUT_FILENO, buf, len);
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
}
