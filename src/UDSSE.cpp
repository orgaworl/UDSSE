/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:10:58
 */
#include "../include/UDSSE.h"

// config
int lambda_ = 1024;
int b_ = 64;
int h_ = 4;

EI ei;
EDB edb;
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
void printBytes(char *buf, int len)
{
	cout << "----------------bytes:----------------\n";
	for (int i = 0; i < len; i++)
	{
		printf("%02x ", (unsigned char)buf[i]);
		if (i % 16 == 15)
		{
			printf("\n");
		}
	}
	printf("\n");
	cout << "--------------------------------\n";
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
int UDSSE_Setup_Client(pairing_t &pairing, char *buf, int lambda)
{
#ifdef NOTE
	printf("SETUP:client\n");
#endif

	// ei.clear();
	// edb.clear();
	// ldb.clear();

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

	char *poi = buf + 4;
	memcpy(poi, pk.c_str(), pk.length());
	poi += pk.length();

	int lenSum = poi - buf;
	*(int *)buf = lenSum;

#ifdef CHECK_BYTES
	printBytes(buf, lenSum);
#endif
	return UDSSE_Setup_Client_Sucess;
}

int UDSSE_Setup_Server(pairing_t &pairing, char *buf)
{
#ifdef NOTE
	printf("SETUP:server\n");
#endif
	// ei.clear();
	// edb.clear();
	// ldb.clear();
	// reveive pk
	int lenSum = *(int *)buf;
	pk = string(buf + 4, lenSum - 4);

#ifdef CHECK_BYTES
	printBytes(buf, lenSum);
#endif
	return UDSSE_Setup_Server_Sucess;
}

// Search Part
int UDSSE_Search_Client(pairing_t &pairing, char *buf, string omega)
{
#ifdef PRINT_RESULT
	printf("--------------------------BEGIN--------------------------\n");
	printf("SEARCH: Search on key word: \"%s\" .\n", omega.c_str());
#endif

	// A.
	if (ldb.count(omega) == 0)
	{
		printf("SEARCH: Fail! No documents contain the key word.\n");
		printf("--------------------------END--------------------------\n");
		return UDSSE_Search_Client_Fail;
	}
	// 复制密钥并计算穿刺密钥
	MSK_S *mskR = new MSK_S(ldb[omega]->msk, pairing);
	SRE_KRev(pairing, mskR, ldb[omega]->D);

#ifdef PRINT
	printf("Search Client mskR\n");
	printMSK(mskR);
#endif

	string Komega = PRF(Ks, omega);
	string ST = ldb[omega]->ST;
	int c = ldb[omega]->c;

	// B. send (msk_R,Komega/tkn,ST,c) to server
	char *poi = buf + 4;
	int len = -1;
	int lenSum = 0;

	string bytes = MSK2Bytes(mskR);
	len = bytes.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, bytes.c_str(), len);
	poi += len;

	len = Komega.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, Komega.c_str(), len);
	poi += len;

	len = ST.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, ST.c_str(), len);
	poi += len;

	*(int *)poi = c;
	poi += sizeof(int);

	lenSum = poi - buf;
	*(int *)buf = lenSum;

#ifdef CHECK_BYTES
	printBytes(buf, lenSum);
#endif

	delete mskR;
	return UDSSE_Search_Client_Sucess;
}
int UDSSE_Search_Server(pairing_t &pairing, char *buf)
{
	// A.接收(msk_R,Komega/tkn,ST,c)
	char *poi = buf;
	int len = -1;
	// int tempLen = 0;

	int lenSum = *(int *)poi;
	poi += sizeof(int);

#ifdef CHECK_BYTES
	printBytes(buf, lenSum);
#endif
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
#ifdef NOTE
		printf("error decode in search\n");
#endif
		return UDSSE_Search_Server_Fail;
	}

	//  B. 执行协议
	len = -1;
	vector<string> Res;
	element_t plainElement;
	element_init_GT(plainElement, pairing);
	for (long long i = 0; i < c; i++)
	{
		// 1. RSA decrypt: bytes-->bytes
		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);

#ifdef CHECK_ST
		printf(" ST UT in serach \n");
		printBytes((char *)ST.c_str(), ST.length());
		printBytes((char *)UT.c_str(), UT.length());
#endif
		if (ei.count(UT) == 0)
		{
			printf("      | %d not exist in EI. \n", i + 1);
		}
		else
		{
			string plain(ei[UT]->e);
			len = plain.length();
			// for (int i = 0; i < len; i++)
			// {
			// 	plain[i] ^= stream[i % HASH2_LENGTH];
			// }

			// 2. transform: bytes --> CT_S
			CT_S *ct = Bytes2CT(pairing, plain);
			if (ct != DECODE_FAIL)
			{
				// 3. decrypt: bytes --> element
				int mark = SRE_Dec(pairing, mskR, ct, plainElement);
				if (mark == SRE_DEC_FAIL)
				{
#ifdef PRINT_RESULT
					printf("      | %d fail. \n", i + 1);
#endif
				}
				else
				{
#ifdef PRINT_RESULT
					printf("      | %d sucess. \n", i + 1);
#endif
					// 4. element -> bytes(string)
					int tempLen = element_to_bytes((unsigned char *)buf, plainElement);
					Res.push_back(string(buf, tempLen));
				}
			}
			else
			{
#ifdef PRINT_RESULT
				printf("      | %d decode error. \n", i + 1);
#endif
			}

			delete ct;
		}

		if (i != c - 1)
			ST = RsaPubDecrypt(ST, pk);
	}

	// 回显给client
	int m = Res.size();
#ifdef PRINT_RESULT
	printf("SEARCH: server return results(totaly %d). \n", m);
	for (int i = 0; i < m; i++)
	{
		cout << "      | " << i + 1 << " :" << Res[i] << endl;
	}
	printf("--------------------------END--------------------------\n");
#endif
	element_clear(plainElement);
	return UDSSE_Search_Client_Sucess;
}

//  Update Part
int UDSSE_Update_Client(pairing_t &pairing, char *buf, OP_TYPE op, string omega, string ind, int d)
{
#ifdef NOTE
	printf("UPDATE:client\n");
#endif
	// A.
	if (ldb.count(omega) == 0)
	{
		// 不存在则创建
		LDB_ENTRY *entry = new LDB_ENTRY();
		SRE_KGen(pairing, entry->msk, lambda_, b_, h_, d); // MSK
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
	for (int i = 0; i < ind.length(); i++)
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
		if (bytes == ENCODE_FAIL)
			return UDSSE_Update_Client_Fail;
		// RSA sk decry: bytes --> bytes

		string Komega = PRF(Ks, omega);
		if (ldb[omega]->ST.length() == 0) // 若ST为空,则创建随机串并设c为0
		{
			char buf[ST_LEN];
			for (int i = 0; i < ST_LEN; i++)
			{
				buf[i] = rand();
			}
			ldb[omega]->c = 0;					  // c
			ldb[omega]->ST = string(buf, ST_LEN); // ST
		}
		string ST = RsaPriEncrypt(ldb[omega]->ST, sk);
		ldb[omega]->c += 1;
		ldb[omega]->ST = ST;

		std::string UT = HMAC_SHA256(Komega, ST);
		std::string stream = HMAC_MD5(Komega, ST);
		int len = bytes.length();
		// std::string e(len, '\0');
		// for (int i = 0; i < len; i++)
		// {
		// 	bytes[i] ^= stream[i % HASH2_LENGTH];
		// }
#ifdef CHECK_D
		printf("D In Update Client. \n");
		printBytes((char *)bytes.c_str(), bytes.length());
#endif
#ifdef CHECK_ST
		printf(" ST UT in update \n");
		printBytes((char *)ST.c_str(), ST.length());
		printBytes((char *)UT.c_str(), UT.length());
		// printBytes((char *)stream.c_str(), stream.length());
#endif
#ifdef CHECK_E
		printf("E In Update Client. \n");
		printBytes((char *)e.c_str(), e.length());
#endif

		// B. send UT and e
		char *poi = buf + 4;
		// UT
		len = UT.length();
		*(int *)poi = len;
		poi += sizeof(int);
		memcpy(poi, UT.c_str(), len);
		poi += len;
		// e
		len = bytes.length();
		*(int *)poi = len;
		poi += sizeof(int);
		memcpy(poi, bytes.c_str(), len);
		poi += len;

		int lenSum = poi - buf;
		*(int *)buf = lenSum;
#ifdef CHECK_BYTES
		printBytes(buf, lenSum);
#endif
	}

	return UDSSE_Update_Client_Sucess;
}

int UDSSE_Update_Server(pairing_t &pairing, char *buf)
{
#ifdef NOTE
	printf("UPDATE:server\n");
#endif
	// A. receive UT and e
	char *poi = buf;
	int len = -1;
	int lenSum = *(int *)poi;
	poi += sizeof(int);

#ifdef CHECK_BYTES
	printBytes(buf, lenSum);
#endif
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
		printf("error decode in up \n");
		return UDSSE_Update_Server_Fail;
	}

	// B. 存储
	if (ei.count(UT) == 0)
	{
		ei[UT] = new EI_ENTRY();
	}
	ei[UT]->e = e;

#ifdef CHECK_E
	printf("E In Update Server. \n");
	printBytes((char *)e.c_str(), e.length());
#endif
	return UDSSE_Update_Server_Sucess;
}

// Update Key Part
int UDSSE_UpdateKey_Client(pairing_t &pairing, char *buf, string omega)
{
#ifdef NOTE
	printf("KEY UPDATE:client\n");
#endif
	LDB_ENTRY *entry = NULL;
	if (ldb.count(omega) == 0)
	{
		// 策略1 不存在则结束
		return UDSSE_UpdateKey_Client_Fail;

		// 策略2 不存在则创建
		// entry = new LDB_ENTRY();
		// SRE_KGen(pairing, entry->msk, lambda_, b_, h_, 1); // MSK
		// ldb.insert(pair<string, LDB_ENTRY *>(omega, entry));
	}
	entry = ldb[omega];
	token *tk;
	UPE_UPDATE_SK(pairing, entry->msk->pp, entry->msk->sk, tk);
	string Komega = PRF(Ks, omega);
	int c = ldb[omega]->c;
	string ST = ldb[omega]->ST;

	// B. send token,Komega/tkn,ST,c
	char *poi = buf + 4;
	int len = -1;
	int lenSum = 0;
	// TOKEN
	string tokenBytes = Token2Bytes(tk);
	len = tokenBytes.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, tokenBytes.c_str(), len);
	poi += len;
	// PP
	string PP = PP2Bytes(entry->msk->pp);
	len = PP.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, PP.c_str(), len);
	poi += len;
	// Komega
	len = Komega.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, Komega.c_str(), len);
	poi += len;
	// ST
	len = ST.length();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, ST.c_str(), len);
	poi += len;

	*(int *)poi = c;
	poi += sizeof(int);

	lenSum = poi - buf;
	*(int *)buf = lenSum;

	return UDSSE_UpdateKey_Client_Sucess;
}

int UDSSE_UpdateKey_Server(pairing_t &pairing, char *buf)
{
#ifdef NOTE
	printf("KEY UPDATE:server\n");
#endif

	// A. receive
	char *poi = buf;
	int len = -1;
	int lenSum = *(int *)poi;
	poi += sizeof(int);
	// token
	len = *(int *)poi;
	poi += sizeof(int);
	token *tk = Bytes2Token(pairing, poi);
	poi += len;
	if (tk == DECODE_FAIL)
		return UDSSE_UpdateKey_Server_Fail;
	// PP
	len = *(int *)poi;
	poi += sizeof(int);
	PP_S *pp = Bytes2PP(pairing, poi);
	poi += len;
	if (pp == DECODE_FAIL)
		return UDSSE_UpdateKey_Server_Fail;
	// Komega
	len = *(int *)poi;
	poi += sizeof(int);
	string Komega(poi, len);
	poi += len;
	// ST
	len = *(int *)poi;
	poi += sizeof(int);
	string ST(poi, len);
	poi += len;
	// c
	int c = *(int *)poi;
	poi += sizeof(int);
	// check
	if (lenSum != poi - buf)
	{
		printf("!!! error decode in upk 1\n");
		return UDSSE_UpdateKey_Server_Fail;
	}

	// B. process
	for (long long j = 0; j < c; j++)
	{
		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);

		if (ei.count(UT) != 0)
		{
			// 1. trans to ct
			string plain(ei[UT]->e);
			len = plain.length();

#ifdef CHECK_E
			printf("E In UpdateKey Server 1. \n");
			printBytes((char *)plain.c_str(), plain.length());
#endif
			// for (int i = 0; i < len; i++)
			// {
			// 	plain[i] ^= stream[i % HASH2_LENGTH];
			// }

#ifdef CHECK_D
			printf("D In UpdateKey Server 1. \n");
			printBytes((char *)plain.c_str(), plain.length());
#endif
			CT_S *ct = Bytes2CT(pairing, plain);
			if (ct == DECODE_FAIL)
			{
				printf("!!! error decode in upk 2\n");
				return UDSSE_UpdateKey_Server_Fail;
			}

			// 2. update ct
			UPE_UPDATE_CT(pairing, pp, ct, tk); // PP

			// 3. trans to bytes
			string newCipher = CT2Bytes(ct);
			if (newCipher == ENCODE_FAIL)
			{
				printf("!!! error encode in upk 3\n");
				return UDSSE_UpdateKey_Server_Fail;
			}

			len = newCipher.length();
#ifdef CHECK_D
			printf("D In UpdateKey Server 2. \n");
			printBytes((char *)newCipher.c_str(), newCipher.length());
#endif
			// for (int i = 0; i < len; i++)
			// {
			// 	newCipher[i] ^= stream[i % HASH2_LENGTH];
			// }
			ei[UT]->e = newCipher;

#ifdef CHECK_E
			printf("E In UpdateKey Server 2. \n");
			printBytes((char *)newCipher.c_str(), newCipher.length());
#endif
			delete ct;
		}
		// 4.下一个加密数据项
		if (j != c - 1)
			ST = RsaPubDecrypt(ST, pk);
	}
	return UDSSE_UpdateKey_Server_Sucess;
}

string SK2Bytes(SK_S *sk)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4; // 留出4字节存储总长度
	int len = -1;

	*(int *)poi = sk->i;
	poi += sizeof(int);

	len = element_to_bytes((unsigned char *)poi, sk->galpha);
	poi += len;

	len = element_to_bytes((unsigned char *)poi, sk->sk0);
	poi += len;

	int i = sk->i;
	for (int j = 0; j < i + 1; j++)
	{
		for (int k = 0; k < 3; k++)
		{
			len = element_to_bytes((unsigned char *)poi, sk->SKmain[j][k]);
			poi += len;
			if (len == 0)
			{
				printf("!!! error in sk2bytes !!!\n");
			}
		}
	}
	int lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	return string(bytes, lenSum);
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

	len = element_from_bytes(sk->galpha, (unsigned char *)poi);
	poi += len;

	len = element_from_bytes(sk->sk0, (unsigned char *)poi);
	poi += len;

	for (int j = 0; j < i + 1; j++)
	{
		for (int k = 0; k < 3; k++)
		{
			test = element_from_bytes(sk->SKmain[j][k], (unsigned char *)poi);
			poi += test;
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
		len = element_to_bytes((unsigned char *)poi, pp->PP[i]);
		poi += len;
	}

	lenSum = poi - bytes;
	*(int *)bytes = lenSum;
	return string(bytes, lenSum);
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
		// len = *(int *)poi;
		// poi += sizeof(int);
		len = element_from_bytes(pp->PP[i], (unsigned char *)poi);
		poi += len;
	}
	if (lenSum != poi - bytes)
	{
		printf("decode error in pp\n");
		return DECODE_FAIL;
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

	return string(bytes, lenSum);
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

#ifdef PRINT
	printf("trans from msk\n");
	printStr(res);
#endif
	return string(buf, lenSum);
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
	SK_S *sk = Bytes2SK(pairing, poi);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	PP_S *pp = Bytes2PP(pairing, poi);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	H_S *h = Bytes2H(poi);
	poi += len;

	len = *(int *)poi;
	poi += sizeof(int);
	B_S *b = Bytes2B(poi);
	poi += len;

	if (lenSum != poi - bytes)
	{
		printf("decode error in msk\n");
		return DECODE_FAIL;
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
	int eleLen = -1;
	int lenSum = 0;

	// 1. 存储d
	int d = ct->d;
	*(int *)poi = d;
	poi += sizeof(int);

	for (int i = 0; i < d + 2; i++)
	{
		eleLen = element_to_bytes((unsigned char *)poi, ct->CT[i]);
		poi += eleLen;
	}
	for (int i = 0; i < d; i++)
	{
		eleLen = element_to_bytes((unsigned char *)poi, ct->tagList[i]);
		poi += eleLen;
	}
	lenSum = poi - bytes;
	*(int *)bytes = lenSum;

	return string(bytes, lenSum);
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
		tempLen = element_from_bytes(ct->CT[i], (unsigned char *)poi);
		poi += tempLen;
	}
	for (int i = 0; i < d; i++)
	{
		tempLen = element_from_bytes(ct->tagList[i], (unsigned char *)poi);
		poi += tempLen;
	}
	if (lenSum != poi - bytes)
	{
		printf("decode error %d %d\n", lenSum, poi - bytes);
		return DECODE_FAIL;
	}
	return ct;
}

string Token2Bytes(token *tk)
{
	char bytes[TRANS_BUF_SIZE];
	char *poi = bytes + 4;
	int len = -1;
	int lenSum = 0;

	len = element_to_bytes((unsigned char *)poi, tk->d_alpha);
	poi += len;

	len = element_to_bytes((unsigned char *)poi, tk->galpha);
	poi += len;

	lenSum = poi - bytes;
	*(int *)bytes = lenSum;

	return string(bytes, lenSum);
}
token *Bytes2Token(pairing_t &pairing, char *bytes)
{
	int len = 0;
	int testLen = 0;
	char *poi = bytes;
	token *tk = new token(pairing);

	int lenSum = *(int *)poi;
	poi += sizeof(int);

	testLen = element_from_bytes(tk->d_alpha, (unsigned char *)poi);
	poi += testLen;

	testLen = element_from_bytes(tk->galpha, (unsigned char *)poi);
	poi += testLen;

	if (poi - bytes != lenSum)
	{
		delete tk;
		return DECODE_FAIL;
	}
	return tk;
}