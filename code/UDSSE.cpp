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
	memcpy(buf, pk.c_str(), pk.size());
	send(sfd, buf, pk.size(), 0);

	return 0;
}
int UDSSE_Setup_Server(pairing_t &pairing, int sfd)
{
	// reveive pk
	printf("mark1");
	char buf[TRANS_BUF_SIZE];
	int len = read(sfd, buf, sizeof(buf));
	pk = string(buf, len);
	printf("mark2");
	return 0;
}

// Search Part
int UDSSE_Search_Client(pairing_t &pairing, int sfd, string omega)
{
	// A. 
	if (ldb.count(omega) == 0)
	{
		return -1;
	}
	//LDB_ENTRY *entry = &ldb[omega];
	MSK_S *mskR = new MSK_S(*(ldb[omega]->msk));
	vector<element_t>temp;
	MSK_S *sk;
	SRE_KRev(pairing, mskR, ldb[omega]->D);
	string Komega = PRF(Ks, omega);

	int c = ldb[omega]->c;
	string ST = ldb[omega]->ST;


	// B. send (msk_R,Komega/tkn,ST,c) to server
	char buf[TRANS_BUF_SIZE];
	char *poi = buf;
	int len = -1;

	string bytes = MSK2Bytes(mskR);
	len = bytes.size();
	*(int *)poi = len;
	poi += sizeof(int);
	memcpy(poi, bytes.c_str(), len);
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

	send(sfd, buf, TRANS_BUF_SIZE, 0);
	return 0;
}
int UDSSE_Search_Server(pairing_t &pairing, int sfd)
{

	// A.接收(msk_R,Komega/tkn,ST,c)
	char buf[TRANS_BUF_SIZE];
	int totalLen = read(sfd, buf, sizeof(buf));
	char *poi = buf;
	int len = -1;

	len = *(int *)poi;
	poi += sizeof(int);
	MSK_S *mskR = Bytes2MSK(pairing,poi);
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

	// B. 执行协议

	// bytes            bytes           CT_S(element[] )    	  element                   bytes
	//      --RSA解密-->     --转化-->                --ECC解密-->            --转化为字节码-->
	len = -1;
	// vector<element_t> Res_tag;
	vector<string> Res_plain; //{tag,ct} 集合

	// 1. RSA解密
	for (long long i = 0; i <= c; i++)
	{

		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);
		string plain(edb[UT]->e);

		len = plain.length();
		for (int i = 0; i < len; i++)
		{
			plain[i] = plain[i] ^ stream[i % HASH2_LENGTH];
		}
		// Res_tag.push_back(edb[UT].tag);
		Res_plain.push_back(plain);
		ST = rsa_pub_encrypt(ST, pk);
	}

	// 2. 将字节转化为element array
	len = Res_plain.size();
	vector<CT_S *> Res_ct(len);
	for (int i = 0; i < len; i++)
	{
		Res_ct[i] = Bytes2CT(pairing, Res_plain[i]);
	}
	// 此时得到 {(tag,ct),...}

	// 3. ECC 解密
	int m = Res_plain.size();
	element_t plain;
	element_init_GT(plain, pairing);

	vector<element_t*> Res_tag_dec;
	vector<string> Res_plain_dec;
	for (int i = 0; i < m; i++)
	{
		int mark = SRE_Dec(pairing, mskR, Res_ct[i], plain);
		if (mark == SRE_DEC_SUCCESS)
		{
			// ind
			element_to_bytes((unsigned char *)buf, plain);
			string tempstr = buf;
			Res_plain_dec.push_back(tempstr);

			// tag
			Res_tag_dec.push_back(Res_ct[i]->tagList);
		}
	}
	// 回显给client
	len = Res_tag_dec.size();
	for (int i = 0; i < len; i++)
	{
		sprintf(buf, "%s", Res_plain_dec[i].c_str());
		write(sfd, buf, strlen(buf));
	}

	return 0;
}

//  Update Part
int UDSSE_Update_Client(pairing_t &pairing, int sfd, OP_TYPE op, string omega, string ind)
{

	// A. 
	if (ldb.count(omega) == 0)
	{
		// 不存在则创建
		LDB_ENTRY *entry=new LDB_ENTRY();
		SRE_KGen(pairing, entry->msk, lambda_, b_, h_, 1); // MSK
		ldb.insert(pair<string, LDB_ENTRY*>(omega, entry));
	}
	// 计算PRF值(tag)
	string tagBytes = PRF(Kt, omega + ind);

	// tag转化到ECC上
	element_t tag;
	element_init_Zr(tag, pairing);
	element_from_hash(tag, (void *)tagBytes.c_str(), TAG_LEN);
	element_t *tagList;
	tagList = &tag;

	// DEL OP or Other OP
	if (op == OP_DEL)
	{
		ldb[omega]->D.push_back(&tag);
	}
	else if (op != OP_ADD && op != OP_DEL)
	{
		printf("NOT SUPPORTED OPERATION ! ");
	}

	// ADD OP
	if (op == OP_ADD)
	{
		// 计算密文 : bytes --> element --> CT_S
		element_t plain;
		element_init_GT(plain, pairing);
		element_from_hash(plain, (unsigned char *)ind.c_str(), ind.size());
		CT_S *ct;
		SRE_Enc(pairing, ldb[omega]->msk, plain, tagList, ct);

		// CT_S --> bytes
		string bytes = CT2Bytes(ct);

		// RSA sk decry: bytes --> bytes
		std::string Komega = PRF(Ks, omega);
		if (ldb[omega]->ST.length() == 0) // 若ST为空
		{
			char buf[ST_LEN];
			for (int i = 0; i < ST_LEN; i++)
			{
				buf[i] = rand();
			}
			ldb[omega]->c = 0;	 // c
			ldb[omega]->ST = buf; // ST
		}
		else
		{
			ldb[omega]->c += 1;
			ldb[omega]->ST = rsa_pri_decrypt(ldb[omega]->ST, sk);
		}
		std::string ST = ldb[omega]->ST;
		std::string UT = HMAC_SHA256(Komega, ST);
		std::string stream = HMAC_MD5(Komega, ST);

		int len = bytes.length();
		std::string e(len, '\0');
		for (int i = 0; i < len; i++)
		{
			e[i] = bytes[i] ^ stream[i % HASH2_LENGTH];
		}

		// B. send UT and e
		char buf[TRANS_BUF_SIZE];
		char *poi = buf;

		// UT
		len = e.length();
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

		send(sfd, buf, TRANS_BUF_SIZE, 0);
	}
	return 0;
}




int UDSSE_Update_Server(pairing_t &pairing, int sfd)
{
	// A. receive UT and e
	char buf[TRANS_BUF_SIZE];
	int totalLen = read(sfd, buf, sizeof(buf));
	char *poi = buf;

	// UT
	int len = *(int *)poi;
	poi += sizeof(int);
	string UT(poi, len);
	poi += len;

	// e
	len = *(int *)poi;
	poi += sizeof(int);
	string e(poi, len);
	poi += len;

	// B. 存储
	edb[UT]->e = e;
	return 0;
}

// Update Key Part

// int UDSSE_UpdateKey(pairing_t &pairing, int sfd, string omega)
// {
// 	mapValPair *temp = &(MAP[omega]);
// 	if (temp == nullptr)
// 	{
// 		SRE_KGen(pairing, temp->msk, lambda_, b_, h_, d_);
// 		temp->i = 0;
// 		temp->D.clear();
// 	}
// 	token *token;
// 	UPE_UPDATE_SK(pairing, temp->msk->pp, temp->msk->sk, token);

// 	// send token
// 	unsigned char buf[1024];
// 	int len;
// 	len = element_to_bytes(buf, token->d_alpha);
// 	write(sfd, buf, len);
// 	write(sfd, " ", 1);
// 	len = element_to_bytes(buf, token->galpha);
// 	write(sfd, buf, len);
// }





string SK2Bytes(SK_S *sk)
{
    char bytes[TRANS_BUF_SIZE];
    char *poi = bytes;
    int len = -1;
    char buf[128];

    *(int *)poi = sk->i;
    poi += sizeof(int);

    len = element_to_bytes_compressed((unsigned char *)buf, sk->galpha);
    *(int *)poi = len;
    poi += sizeof(int);
    memcpy(poi, buf, len);
    poi += len;

    len = element_to_bytes_compressed((unsigned char *)buf, sk->sk0);
    *(int *)poi = len;
    poi += sizeof(int);
    memcpy(poi, buf, len);
    poi += len;

    int i = sk->i;
    for (int j = 0; j < i; j++)
    {
        for (int k = 0; k < 3; k++)
        {
            len = element_to_bytes_compressed((unsigned char *)buf, sk->SKmain[j][k]);
            *(int *)poi = len;
            poi += sizeof(int);
            memcpy(poi, buf, len);
            poi += len;
        }
    }
    string res = bytes;
    return res;
}
SK_S *Bytes2SK(pairing_t &pairing, char *bytes)
{
    char *poi = bytes;
    int len;

    int i = *(int *)poi;
    poi += sizeof(int);

    SK_S *sk = new SK_S(i, pairing);

    len = *(int *)poi;
    poi += sizeof(int);
    element_from_bytes_compressed(sk->galpha, (unsigned char *)poi);
    poi += len;

    len = *(int *)poi;
    poi += sizeof(int);
    element_from_bytes_compressed(sk->sk0, (unsigned char *)poi);
    poi += len;

    for (int j = 0; j < i; j++)
    {
        for (int k = 0; k < 3; k++)
        {
            len = *(int *)poi;
            poi += sizeof(int);
            element_from_bytes_compressed(sk->SKmain[j][k], (unsigned char *)poi);
            poi += len;
        }
    }
    return sk;
}
string PP2Bytes(PP_S *pp)
{
    char bytes[TRANS_BUF_SIZE];
    char *poi = bytes;
    int len = -1;
    char buf[128];

    *(int *)poi = pp->d;
    poi += sizeof(int);

    // d+3个
    int loop = pp->d + 3;
    for (int i = 0; i < loop; i++)
    {
        len = element_to_bytes_compressed((unsigned char *)buf, pp->PP[i]);
        *(int *)poi = len;
        poi += sizeof(int);
        memcpy(poi, buf, len);
        poi += len;
    }
    string res = bytes;
    return res;
}
PP_S *Bytes2PP(pairing_t &pairing, char *bytes)
{
    char *poi = bytes;
    int len;

    int d = *(int *)poi;
    poi += sizeof(int);

    PP_S *pp = new PP_S(d, pairing);
    int loop = d + 3;
    for (int i = 0; i < loop; i++)
    {
        len = *(int *)poi;
        poi += sizeof(int);
        element_from_bytes_compressed(pp->PP[i], (unsigned char *)poi);
        poi += len;
    }
    return pp;
}
string H2Bytes(H_S *h)
{
    char bytes[TRANS_BUF_SIZE];
    *(int *)bytes = h->h;
    string res = bytes;
    return res;
}
H_S *Bytes2H(char *bytes)
{
    int h = *(int *)bytes;
    H_S *h_s = new H_S(h);
    return h_s;
}
string B2Bytes(B_S *b)
{
    char bytes[TRANS_BUF_SIZE];
    char *poi = bytes;

    //*(int*)poi=b->b;
    // poi+=sizeof(int);

    string main = b->main->to_string();
    memcpy(poi, main.c_str(), main.length());
    string res = bytes;
    return res;
}
B_S *Bytes2B(char *bytes)
{
    char *poi = bytes;

    // int b=*(int*)poi;
    // poi+=sizeof(int);
    // string b(bytes,b_MAX_VALUE/8);
    bitset<b_MAX_VALUE> temp(bytes, b_MAX_VALUE / 8);
    // bitset<b_MAX_VALUE>temp(b);
    B_S *b_s = new B_S(temp);
    return b_s;
}

string MSK2Bytes(MSK_S *msk)
{
    char buf[2048];
    char *poi = buf;
    int len = -1;
    string sk = SK2Bytes(msk->sk);
    string pp = PP2Bytes(msk->pp);
    string h = H2Bytes(msk->H);
    string b = B2Bytes(msk->B);

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

    string res = buf;
    return res;
}
MSK_S *Bytes2MSK(pairing_t &pairing, char *bytes)
{
    char *poi = bytes;
    int len = -1;

    len = *(int *)poi;
    len += sizeof(int);
    string temp(poi, len);
    poi += len;
    SK_S *sk = Bytes2SK(pairing, (char *)temp.c_str());

    len = *(int *)poi;
    poi += sizeof(int);
    temp = string(poi, len);
    poi += len;
    PP_S *pp = Bytes2PP(pairing, (char *)temp.c_str());

    len = *(int *)poi;
    poi += sizeof(int);
    temp = string(poi, len);
    poi += len;
    H_S *h = Bytes2H((char *)temp.c_str());

    len = *(int *)poi;
    poi += sizeof(int);
    temp = string(poi, len);
    poi += len;
    B_S *b = Bytes2B((char *)temp.c_str());

    MSK_S *msk = new MSK_S();
    msk->sk = sk;
    msk->pp = pp;
    msk->H = h;
    msk->B = b;

    return msk;
}

string CT2Bytes(CT_S *ct)
{
    int d = ct->d;
    unsigned char bytes[1024];
    unsigned char *poi = bytes;

    // 临时值
    unsigned char buf[128];
    int eleLen = -1;
    // 1. 存储d
    *(int *)poi = d;
    poi += sizeof(int);
    for (int i = 0; i < d + 2; i++)
    {
        // 2.1 存储每个元素长度
        eleLen = element_to_bytes_compressed(buf, ct->CT[i]);
        *(int *)poi = eleLen;
        poi += sizeof(int);
        // 2.2 存储每个元素的具体内容
        memcpy(poi, buf, eleLen);
        poi += eleLen;
    }
    for (int i = 0; i < d; i++)
    {
        // 2.1 存储每个tag长度
        eleLen = element_to_bytes_compressed(buf, ct->tagList[i]);
        *(int *)poi = eleLen;
        poi += sizeof(int);
        // 2.2 存储每个tag的具体内容
        memcpy(poi, buf, eleLen);
        poi += eleLen;
    }
    string res = (char *)bytes;
    return res;
}

CT_S *Bytes2CT(pairing_t &pairing, string bytes)
{
    int len = -1;
    char *poi = (char *)bytes.c_str();

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
        element_from_bytes_compressed(ct->CT[i], (unsigned char *)poi);
        poi += len;
    }
    for (int i = 0; i < d; i++)
    {
        // 2.1 存储每个tag长度
        len = *(int *)poi;
        poi += sizeof(int);
        // 2.2 内容
        element_from_bytes_compressed(ct->tagList[i], (unsigned char *)poi);
        poi += len;
    }
    return ct;
}
