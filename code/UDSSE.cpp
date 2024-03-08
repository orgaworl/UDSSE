/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:10:58
 */
#include "UDSSE.h"

// config
int lambda_ = 1024;
int b_ = 64;
int h_ = 4;

EDB edb;
EDB edb_cache;
LDB ldb;
string Kt;
string Ks;

// RSA
string sk;
string pk;

// PAIRING
PP_S *pp;

#ifdef OFFLINE
char gbuf[4096];
#endif
void printTag(element_t tag)
{
	cout << "----------------tag:----------------\n";
	element_out_str(stdout, 16, tag);
	cout << "\n--------------------------------\n";
}
void printMSK(MSK_S *mskR)
{
	cout << "----------------MSK:----------------\n";
	cout << "----SK:----\n";
	element_out_str(stdout, 16, mskR->sk->galpha);
	cout << "\n";
	element_out_str(stdout, 16, mskR->sk->sk0);
	cout << "\n";
	for (int ii = 0; ii < mskR->sk->i + 1; ii++)
	{
		element_out_str(stdout, 16, mskR->sk->SKmain[ii][0]);
		cout << "\n";
		element_out_str(stdout, 16, mskR->sk->SKmain[ii][1]);
		cout << "\n";
		element_out_str(stdout, 16, mskR->sk->SKmain[ii][2]);
		cout << "\n";
	}
	cout << "----PP:----\n";
	printf("%d\n", mskR->pp->d);
	for (int i = 0; i < mskR->pp->d + 3; i++)
	{
		element_out_str(stdout, 16, mskR->pp->PP[i]);
		cout << "\n";
	}

	cout << "--------------------------------\n";
}
void printStr(string str)
{
	cout << "----------------STR BYTE----------------\n";
	for (int i = 0; i < str.capacity(); i++)
		cout << hex << (int)(unsigned char)str[i] << " ";
	printf("\n");
	cout << "--------------------------------\n";
}

void printCT(CT_S *ct)
{
	cout << "----------------CT:----------------\n";
	cout << "d: " << ct->d << endl;
	for (int i = 0; i < ct->d + 2; i++)
	{
		element_out_str(stdout, 16, ct->CT[i]);
		printf("\n");
	}
	for (int i = 0; i < ct->d; i++)
	{
		element_out_str(stdout, 16, ct->tagList[i]);
		printf("\n");
	}
	cout << "--------------------------------\n";
}

// Setup Part
int UDSSE_Setup_Client(pairing_t &pairing, int sfd, int lambda, int d)
{
	lambda_ = lambda;

	// gen Ks Kt
	Kt = string(KEY_LEN, 0);
	Ks = string(KEY_LEN, 0);
	for (int i = 0; i < KEY_LEN; i++)
	{
		Kt[i] = rand();
		Ks[i] = rand();
	}

	// gen RSA PPK PSK
	generateRSAKey(pk, sk);

	// send PK to server
	char buf[TRANS_BUF_SIZE];
	char *poi = buf + 4;
	memcpy(poi, pk.c_str(), pk.size());
	poi += pk.size();

	int lenSum = poi - buf;
	*(int *)buf = lenSum;

#ifdef OFFLINE
	memcpy(gbuf, buf, lenSum);
#endif
#ifndef OFFLINE
	send(sfd, buf, pk.size(), 0);
#endif

	return UDSSE_Setup_Client_Sucess;
}
int UDSSE_Setup_Server(pairing_t &pairing, int sfd)
{
	// reveive pk
	char buf[TRANS_BUF_SIZE];

#ifdef OFFLINE
	memcpy(buf, gbuf, TRANS_BUF_SIZE);
#endif
#ifndef OFFLINE
	read(sfd, buf, sizeof(buf));
#endif
	int lenSum = *(int *)buf;
	pk = string(buf + 4, lenSum);

	return UDSSE_Setup_Server_Sucess;
}

// Search Part
int UDSSE_Search_Client(pairing_t &pairing, int sfd, string omega)
{
	printf("SEARCH: search on key word: \"%s\" .\n", omega.c_str());
	// A.
	if (ldb.count(omega) == 0)
	{
		printf("SEARCH: fail !.\n");
		return UDSSE_Search_Client_Fail;
	}
	MSK_S *mskR = new MSK_S(ldb[omega]->msk, pairing);
	SRE_KRev(pairing, mskR, ldb[omega]->D);

#ifdef PRINT
	printf("Search Client mskR\n");
	printMSK(mskR);
#endif

	string Komega = PRF(Ks, omega);
	int c = ldb[omega]->c;
	string ST = ldb[omega]->ST;

	printf("SEARCH: client send search query to the server \n");
	// B. send (msk_R,Komega/tkn,ST,c) to server
	char buf[TRANS_BUF_SIZE];
	char *poi = buf + 4;
	int len = -1;
	int lenSum = 0;

	string bytes = MSK2Bytes(mskR);
	len = bytes.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, bytes.c_str(), len);
	poi += len;

#ifdef PRINT
	printf("SEARCH client MSK BYTES\n");
	printStr(bytes);
#endif

	len = Komega.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, Komega.c_str(), len);
	poi += len;

	len = ST.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, ST.c_str(), len);
	poi += len;

	*(int *)poi = c;
	poi += sizeof(int);

	lenSum = poi - buf;
	*(int *)buf = lenSum;
	*poi = 0;

#ifdef OFFLINE
	memcpy(gbuf, buf, lenSum);
#endif
#ifndef OFFLINE
	send(sfd, buf, TRANS_BUF_SIZE, 0);
#endif
	printf("SEARCH: client finish sending \n");
	return UDSSE_Search_Client_Sucess;
}

int UDSSE_Search_Server(pairing_t &pairing, int sfd)
{
	printf("SEARCH: server start receive .\n");
	// A.接收(msk_R,Komega/tkn,ST,c)
	char buf[TRANS_BUF_SIZE];
	char *poi = buf;
	int len = -1;
	int tempLen = 0;

#ifdef OFFLINE
	memcpy(buf, gbuf, TRANS_BUF_SIZE);
#endif
#ifndef OFFLINE
	read(sfd, buf, sizeof(buf));
#endif

	int lenSum = *(int *)poi;
	poi += sizeof(int);

	len = *(int *)poi;
	poi += sizeof(int);
	MSK_S *mskR = Bytes2MSK(pairing, poi);
	poi += len;

#ifdef PRINT
	printMSK(mskR);
#endif

	len = *(int *)poi;
	poi += sizeof(int);
	string Komega(poi, len);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	string ST(poi, len);
	poi += len;

	int c = *(int *)poi;
	poi += sizeof(int);

	if (lenSum != poi - buf)
	{
		printf("error decode in search\n");
	}
	printf("SEARCH: server finish receiving \n");
	printf("SEARCH: server start searching \n");
	// B. 执行协议
	/*
		 bytes            bytes           CT_S(element[] )    	  element                   bytes
			  --RSA解密-->     --转化-->                --ECC解密-->            --转化为字节码-->
	*/

	len = -1;
	vector<string> Res_plain; //{tag,ct} 集合

	printf("      | rsa decrry. \n");
	// 1. RSA解密
	for (long long i = 0; i <= c; i++)
	{

		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);
#ifdef PRINT
		printf("ST:\n");
		printStr(ST);
		printf("\n");
		// printf("UT:\n");
		// printStr(UT);
		// printf("\n");
		printf("stream:\n");
		printStr(stream);
		printf("\n");
#endif
		if (edb.count(UT) == 0)
		{
			printf("             |  not exist in EDB. \n");
			continue;
		}
		string plain(edb[UT]->e);
		len = plain.length();
		for (int i = 0; i < len; i++)
		{
			plain[i] = plain[i] ^ stream[i % HASH2_LENGTH];
		}
		Res_plain.push_back(plain);

		if (i != c)
		{
			ST = RsaPubDecrypt(ST, pk);
			// ST = rsa_pub_encrypt(ST, pk);
			// ST = rsa_pri_decrypt(ST, sk);
			// ST = rsa_pri_decrypt(ST, sk);
			if (ST == "")
			{
				printf("             |  fail. \n");
			}
			else
			{
				printf("             |  sucess. \n");
			}
		}
	}
	printf("      | transfer. \n");
	// 2. 将字节转化为element array
	len = Res_plain.size();
	vector<CT_S *> Res_ct(len);
	for (int i = 0; i < len; i++)
	{
		Res_ct[i] = Bytes2CT(pairing, Res_plain[i]);
		if (Res_ct[i] == NULL)
		{
			printf("             |  fail. \n");
		}
		else
		{
			printf("             |  sucess. \n");
		}
	}
	// 此时得到 {(tag,ct),...}

	// 3. ECC 解密
	printf("      | pbulic key decrry. \n");
	element_t plain;
	element_init_GT(plain, pairing);

	int m = Res_plain.size();
	vector<string> Res_plain_dec;
	for (int i = 0; i < m; i++)
	{
		int mark = SRE_Dec(pairing, mskR, Res_ct[i], plain);
#ifdef PRINT
		printf("ind in element:\n");
		element_out_str(stdout, 16, plain);
		printf("\n");
#endif
		if (mark == SRE_DEC_SUCCESS)
		{
			printf("             |  sucess. \n");
			// ind
			int tempLen = element_to_bytes((unsigned char *)buf, plain);
			string tempstr(buf, tempLen);
			Res_plain_dec.push_back(tempstr);
		}
		else
		{
			printf("             |  fail. \n");
		}
	}


	
	// 回显给client

	m = Res_plain_dec.size();
	printf("SEARCH: server return results(totaly %d). \n", m);
	for (int i = 0; i < m; i++)
	{
		cout << "      | " << i + 1 << " :" << Res_plain_dec[i] << endl;
	}
	return UDSSE_Search_Client_Sucess;
}

//  Update Part
int UDSSE_Update_Client(pairing_t &pairing, int sfd, OP_TYPE op, string omega, string ind)
{
	// A.
	if (ldb.count(omega) == 0)
	{
		// 不存在则创建
		LDB_ENTRY *entry = new LDB_ENTRY();
		SRE_KGen(pairing, entry->msk, lambda_, b_, h_, 1); // MSK
		ldb.insert(pair<string, LDB_ENTRY *>(omega, entry));
	}
	// 计算PRF值(tag)
	string tagBytes = PRF(Kt, omega + ind);

	// tag转化到ECC上
	element_t *tag = new element_t[1];
	element_init_Zr(*tag, pairing);
	element_from_hash(*tag, (void *)tagBytes.c_str(), TAG_LEN);
	element_t *tagList = tag;

#ifdef PRINT
	printTag(*tag);
#endif

	// DEL OP or Other OP
	if (op == OP_DEL)
	{
		ldb[omega]->D.push_back(tag);
		return UDSSE_Update_Client_Sucess;
	}
	else if (op != OP_ADD && op != OP_DEL)
	{
		printf("NOT SUPPORTED OPERATION ! ");
		return UDSSE_Update_Client_Fail;
	}

	// ADD OP
	string ind_128B(IND_LEN, 0);
	for (int i = 0; i < ind.size(); i++)
	{
		ind_128B[i] = ind[i];
	}
	if (op == OP_ADD)
	{
		// 计算密文 : bytes --> element --> CT_S
		element_t plain;
		element_init_GT(plain, pairing);
		int plainLen = element_from_bytes(plain, (unsigned char *)ind_128B.c_str());
		CT_S *ct;
		SRE_Enc(pairing, ldb[omega]->msk, plain, tagList, ct);
		// CT_S --> bytes
		string bytes = CT2Bytes(ct);

		// RSA sk decry: bytes --> bytes
		string ST;
		std::string Komega = PRF(Ks, omega);
		if (ldb[omega]->ST.size() == 0) // 若ST为空
		{
			char buf[ST_LEN];
			for (int i = 0; i < ST_LEN; i++)
			{
				buf[i] = rand();
			}
			ldb[omega]->c = 0;					  // c
			ldb[omega]->ST = string(buf, ST_LEN); // ST
#ifdef PRINT
			printf("rand ST\n");
#endif
		}
		else
		{
#ifdef PRINT
			printf("gene ST\n");
#endif
			ldb[omega]->c += 1;
			// ldb[omega]->ST = rsa_pri_decrypt(ldb[omega]->ST, sk);
			// ST = rsa_pub_encrypt(ldb[omega]->ST, pk);
			// ldb[omega]->ST = rsa_pub_encrypt(ldb[omega]->ST, sk);
			ST = RsaPriEncrypt(ldb[omega]->ST, sk);
			if (ST == "")
			{
				printf(" **** rsa encry error **** \n");
			}
			else
			{
				ldb[omega]->ST = ST;
			}
		}
		ST = ldb[omega]->ST;
		std::string UT = HMAC_SHA256(Komega, ST);
		std::string stream = HMAC_MD5(Komega, ST);
#ifdef PRINT
		printf("%s\n", (char *)omega.c_str());
		printStr(ST);
		printf("\n");
		printf("UT:\n");
		printStr(UT);
		printf("\n");
		printf("stram:\n");
		printStr(stream);
		printf("\n");
#endif
		int len = bytes.length();
		std::string e(len, '\0');
		for (int i = 0; i < len; i++)
		{
			e[i] = bytes[i] ^ stream[i % HASH2_LENGTH];
		}

		// B. send UT and e
		char buf[TRANS_BUF_SIZE];
		char *poi = buf + 4;

		// UT
		len = UT.length();
		*(int *)poi = len;
		poi += sizeof(int);
		memcpy(poi, UT.c_str(), len);
		poi += len;
		// e
		len = e.length();
		*(int *)poi = len;
		poi += sizeof(int);
		memcpy(poi, e.c_str(), len);
		poi += len;

		//
		int lenSum = poi - buf;
		*(int *)buf = lenSum;

#ifdef OFFLINE
		memcpy(gbuf, buf, lenSum);
#endif
#ifndef OFFLINE
		send(sfd, buf, TRANS_BUF_SIZE, 0);
#endif
	}
	return UDSSE_Update_Client_Sucess;
}

int UDSSE_Update_Server(pairing_t &pairing, int sfd)
{
	// A. receive UT and e
	char buf[TRANS_BUF_SIZE];
	char *poi = buf;
	int len = -1;

#ifdef OFFLINE
	memcpy(buf, gbuf, TRANS_BUF_SIZE);
#endif
#ifndef OFFLINE
	read(sfd, buf, sizeof(buf));
#endif

	int lenSum = *(int *)poi;
	poi += sizeof(int);

	// UT
	len = *(int *)poi;
	poi += sizeof(int);
	string UT(poi, len);
	poi += len;
	// e
	len = *(int *)poi;
	poi += sizeof(int);
	string e(poi, len);
	poi += len;

	// check
	if (lenSum != poi - buf)
	{
		printf("error decode in update\n");
		return UDSSE_Update_Server_Fail;
	}
	// B. 存储
	if (edb.count(UT) == 0)
	{
		edb[UT] = new EDB_ENTRY();
	}
	edb[UT]->e = e;
	return UDSSE_Update_Server_Sucess;
}

// Update Key Part

int UDSSE_UpdateKey_Client(pairing_t &pairing, int sfd, string omega)
{
	LDB_ENTRY *entry = NULL;
	if (ldb.count(omega) == 0)
	{
		// 不存在则创建
		entry = new LDB_ENTRY();
		SRE_KGen(pairing, entry->msk, lambda_, b_, h_, 1); // MSK
		ldb.insert(pair<string, LDB_ENTRY *>(omega, entry));
	}

	token *token;
	UPE_UPDATE_SK(pairing, entry->msk->pp, entry->msk->sk, token);

	string Komega = PRF(Ks, omega);
	int c = ldb[omega]->c;
	string ST = ldb[omega]->ST;

	// B. send token,Komega/tkn,ST,c
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;
	char buf[MAX_BUF_SIZE];
	int len;
	int lenSum = 0;

	string tokenBytes = Token2Bytes(token);
	len = tokenBytes.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, tokenBytes.c_str(), len);
	poi += len;

	len = Komega.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, Komega.c_str(), len);
	poi += len;

	len = ST.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, ST.c_str(), len);
	poi += len;

	*(int *)poi = c;
	poi += sizeof(int);

	lenSum = poi - bytes;
	*(int *)bytes = lenSum;

#ifdef OFFLINE
	memcpy(gbuf, bytes, lenSum);
#endif
#ifndef OFFLINE
	write(sfd, buf, lenSum);
#endif
	return UDSSE_UpdateKey_Client_Sucess;
}

int UDSSE_UpdateKey_Server(pairing_t &pairing, int sfd)
{
	// A. receive
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes;
	int len = -1;

#ifdef OFFLINE
	memcpy(bytes, gbuf, TRANS_BUF_SIZE);
#endif
#ifndef OFFLINE
	read(sfd, bytes, TRANS_BUF_SIZE);
#endif
	int lenSum = *(int *)poi;
	poi += sizeof(int);

	len = *(int *)poi;
	poi += sizeof(int);
	token *tk = Bytes2Token(pairing, poi);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	string Komega(poi, len);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	string ST(poi, len);
	poi += len;

	int c = *(int *)poi;
	poi += sizeof(int);

	if (lenSum != poi - bytes)
		printf("error decode in search\n");

	// B. process
	printf("      | rsa decrry. \n");
	for (long long i = 0; i <= c; i++)
	{
		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);
		if (edb.count(UT) == 0)
		{
			continue;
		}
		string plain(edb[UT]->e);

		// 1. oplus decrypt
		len = plain.length();
		for (int i = 0; i < len; i++)
		{
			plain[i] = plain[i] ^ stream[i % HASH2_LENGTH];
		}

		// 2. bytes to CT_S
		CT_S *ct;
		ct = Bytes2CT(pairing, plain);
		// 3. Update
		UPE_UPDATE_CT(pairing, pp, ct, tk); // PP
		// 4. CT_S to Bytes
		plain = CT2Bytes(ct);
		delete ct;

		// 5. oplus encrypt and restore
		for (int i = 0; i < len; i++)
		{
			plain[i] = plain[i] ^ stream[i % HASH2_LENGTH];
		}
		edb[UT]->e = plain;

		// 4.下一个加密数据项
		if (i != c)
		{
			ST = RsaPubDecrypt(ST, pk);
		}
	}
	return UDSSE_UpdateKey_Server_Sucess;
}

string SK2Bytes(SK_S *sk)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4; // 留出4字节存储总长度

	int len = -1;
	char buf[MAX_BUF_SIZE];

	*(int *)poi = sk->i;
	poi += sizeof(int);

	len = element_to_bytes((unsigned char *)buf, sk->galpha);
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, buf, len);
	poi += len;

	len = element_to_bytes((unsigned char *)buf, sk->sk0);
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, buf, len);
	poi += len;

	int i = sk->i;
	for (int j = 0; j < i + 1; j++)
	{
		for (int k = 0; k < 3; k++)
		{
			len = element_to_bytes((unsigned char *)buf, sk->SKmain[j][k]);
			*(int *)poi = len;
			poi += sizeof(int);
			memcpy(poi, buf, len);
			poi += len;
			if (len == 0)
			{
				printf("zero");
			}
		}
	}

	int lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	string res(bytes, lenSum);
	return res;
}
SK_S *Bytes2SK(pairing_t &pairing, char *bytes)
{
	char *poi = bytes;
	int len;
	int test;

	int lenSum = *(int *)poi;
	poi += sizeof(int);

	int i = *(int *)poi;
	poi += sizeof(int);

	SK_S *sk = new SK_S(i, pairing);

	len = *(int *)poi;
	poi += sizeof(int);
	element_from_bytes(sk->galpha, (unsigned char *)poi);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	element_from_bytes(sk->sk0, (unsigned char *)poi);
	poi += len;

	for (int j = 0; j < i + 1; j++)
	{
		for (int k = 0; k < 3; k++)
		{
			len = *(int *)poi;
			poi += sizeof(int);
			test = element_from_bytes(sk->SKmain[j][k], (unsigned char *)poi);
			poi += len;
			if (test != len)
			{
				printf("******** decode error*************\n");
				return DECODE_FAIL;
			}
		}
	}
	if (lenSum != poi - bytes)
	{
		printf("decode error in sk\n");
	}
	return sk;
}
string PP2Bytes(PP_S *pp)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;
	int len = -1;
	int lenSum = 0;
	char buf[MAX_BUF_SIZE];

	*(int *)poi = pp->d;
	poi += sizeof(int);

	// d+3个
	int loop = pp->d + 3;
	for (int i = 0; i < loop; i++)
	{
		len = element_to_bytes((unsigned char *)buf, pp->PP[i]);
		*(int *)poi = len;
		poi += sizeof(int);
		memcpy(poi, buf, len);
		poi += len;
	}

	lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	*poi = 0;
	string res(bytes, lenSum);
	return res;
}
PP_S *Bytes2PP(pairing_t &pairing, char *bytes)
{
	char *poi = bytes;
	int len;

	int lenSum = *(int *)poi;
	poi += sizeof(int);
	int d = *(int *)poi;
	poi += sizeof(int);

	PP_S *pp = new PP_S(d, pairing);
	int loop = d + 3;
	for (int i = 0; i < loop; i++)
	{
		len = *(int *)poi;
		poi += sizeof(int);
		element_from_bytes(pp->PP[i], (unsigned char *)poi);
		poi += len;
	}
	if (lenSum != poi - bytes)
	{
		printf("decode error in pp\n");
	}
	return pp;
}
string H2Bytes(H_S *h)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;

	*(int *)poi = h->h;
	poi += sizeof(int);

	int lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	string res(bytes, lenSum);
	return res;
}
H_S *Bytes2H(char *bytes)
{
	int lenSum = *(int *)bytes;
	int h = *(int *)(bytes + 4);
	H_S *h_s = new H_S(h);
	return h_s;
}
string B2Bytes(B_S *b)
{
	// char bytes[TRANS_BUF_SIZE];
	// uint8_t temp;
	// for(int i=0;i<b_MAX_VALUE;i++)
	// {
	// 	if(i%8==0)
	// 	{
	// 		bytes[i/8]=temp;
	// 		temp=0;
	// 	}
	// 	temp=temp<<1;
	// 	temp=temp|(b->main[i]==true);
	// }
	string res = b->main->to_string();
	return res;
}
B_S *Bytes2B(char *bytes)
{
	bitset<b_MAX_VALUE> temp(bytes);
	B_S *b = new B_S(temp);
	return b;
}

string MSK2Bytes(MSK_S *msk)
{
	char buf[TRANS_BUF_SIZE];
	char *poi = buf + 4;
	int len = -1;
	int lenSum = 0;
	string sk = SK2Bytes(msk->sk);
	string pp = PP2Bytes(msk->pp);
	string h = H2Bytes(msk->H);
	string b = B2Bytes(msk->B);
#ifdef PRINT
	printf("trans from sk\n");
	printStr(sk);
#endif
	len = sk.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, sk.c_str(), len);
	poi += len;

	len = pp.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, pp.c_str(), len);
	poi += len;

	len = h.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, h.c_str(), len);
	poi += len;

	len = b.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, b.c_str(), len);
	poi += len;

	lenSum = poi - buf;
	*(int *)buf = lenSum;
	string res(buf, lenSum);
#ifdef PRINT
	printf("trans from msk\n");
	printStr(res);
#endif
	return res;
}
MSK_S *Bytes2MSK(pairing_t &pairing, char *bytes)
{
	char *poi = bytes;
	int len = -1;
	char buf[MAX_BUF_SIZE];

	int lenSum = *(int *)poi;
	poi += sizeof(int);
#ifdef PRINT
	printf("trans to msk \n");
	string temp(poi, lenSum);
	printStr(temp);
#endif

	len = *(int *)poi;
	poi += sizeof(int);
	memcpy(buf, poi, len);
	poi += len;
	SK_S *sk = Bytes2SK(pairing, buf);

	len = *(int *)poi;
	poi += sizeof(int);
	memcpy(buf, poi, len);
	poi += len;
	PP_S *pp = Bytes2PP(pairing, buf);

	len = *(int *)poi;
	poi += sizeof(int);
	memcpy(buf, poi, len);
	poi += len;
	H_S *h = Bytes2H(buf);

	len = *(int *)poi;
	poi += sizeof(int);
	memcpy(buf, poi, len);
	poi += len;
	B_S *b = Bytes2B(buf);

	if (lenSum != poi - bytes)
	{
		printf("decode error in msk\n");
	}
	MSK_S *msk = new MSK_S();
	msk->sk = sk;
	msk->pp = pp;
	msk->H = h;
	msk->B = b;

	return msk;
}

string CT2Bytes(CT_S *ct)
{
	// 临时值
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;
	unsigned char buf[MAX_BUF_SIZE];
	int eleLen = -1;
	int lenSum = 0;

	// 1. 存储d
	int d = ct->d;
	*(int *)poi = d;
	poi += sizeof(int);

	for (int i = 0; i < d + 2; i++)
	{
		eleLen = element_to_bytes(buf, ct->CT[i]);
		// 2.1 存储每个元素长度
		*(int *)poi = eleLen;
		poi += sizeof(int);
		// 2.2 存储每个元素的具体内容
		memcpy(poi, buf, eleLen);
		poi += eleLen;
	}
	for (int i = 0; i < d; i++)
	{
		eleLen = element_to_bytes(buf, ct->tagList[i]);
		// 2.1 存储每个tag长度
		*(int *)poi = eleLen;
		poi += sizeof(int);
		// 2.2 存储每个tag的具体内容
		memcpy(poi, buf, eleLen);
		poi += eleLen;
	}
	lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	string res(bytes, lenSum);
	return res;
}

CT_S *Bytes2CT(pairing_t &pairing, string str)
{
	int len = -1;
	int tempLen;
	char *bytes = (char *)str.c_str();
	char *poi = bytes;

	int lenSum = *(int *)poi;
	poi += sizeof(int);
	// 1. d
	int d = *(int *)poi;
	poi += sizeof(int);

	CT_S *ct = new CT_S(d, pairing);
	for (int i = 0; i < d + 2; i++)
	{
		// 2.1 长度
		len = *(int *)poi;
		poi += sizeof(int);

		// 2.2 内容
		tempLen = element_from_bytes(ct->CT[i], (unsigned char *)poi);
		if (tempLen != len)
		{
			printf("decode error in ct 1\n");
		}
		poi += len;
	}
	for (int i = 0; i < d; i++)
	{
		// 2.1 存储每个tag长度
		len = *(int *)poi;
		poi += sizeof(int);
		// 2.2 内容
		tempLen = element_from_bytes(ct->tagList[i], (unsigned char *)poi);
		if (tempLen != len)
		{
			printf("decode error in ct 2\n");
		}
		poi += len;
	}
	if (lenSum != poi - bytes)
	{
		printf("decode error in ct 3\n");
	}
	return ct;
}

string Token2Bytes(token *tk)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;
	int len = -1;
	int lenSum = 0;

	len = element_to_bytes((unsigned char *)poi + 4, tk->d_alpha);
	*(int *)poi = len;
	poi += sizeof(int);
	poi += len;

	len = element_to_bytes((unsigned char *)poi + 4, tk->galpha);
	*(int *)poi = len;
	poi += sizeof(int);
	poi += len;

	lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	string res(bytes, lenSum);
	return res;
}
token *Bytes2Token(pairing_t &pairing, char *bytes)
{
	int len = 0;
	int testLen = 0;
	char *poi = bytes;
	token *tk = new token(pairing);

	int lenSum = *(int *)poi;
	poi += sizeof(int);

	len = *(int *)poi;
	poi += sizeof(int);
	testLen = element_from_bytes(tk->d_alpha, (unsigned char *)poi);
	if (len != testLen)
	{
		delete tk;
		return DECODE_FAIL;
	}
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	testLen = element_from_bytes(tk->galpha, (unsigned char *)poi);
	if (len != testLen)
	{
		delete tk;
		return DECODE_FAIL;
	}
	poi += len;

	if (poi - bytes != lenSum)
	{
		delete tk;
		return DECODE_FAIL;
	}
	return tk;
}