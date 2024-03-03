/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-03-03 14:24:15
 */
#include<stdio.h>
#include <bits/stdc++.h>
#include <iostream>
using namespace std;
class cls
{
public:
    int *a;
    int num;
    cls()
    {
        a=NULL;
        num=0;
    }
};
int innerFunc(int*&a)
{
    a=new int[100];
}
int func(cls*in)
{
    innerFunc(in->a);
}

int main()
{
    cls *temp = new cls;
    func(temp);
    return 0;
}