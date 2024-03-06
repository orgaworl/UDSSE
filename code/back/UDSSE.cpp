/*
 * @Author: orgaworl
 * @Email: orgaworl@outlook.com
 * @Date: 2024-02-18 17:10:58
 */
#include "UDSSE.h"


// Setup Part
int UDSSE_Setup_Client(pairing_t &pairing, int sfd, int lambda, int d, std::string pk, std::string sk, string Kt, string Ks)
{
	lambda_=lambda;
	generateRSAKey(pk, sk);
	Kt=string(KEY_LEN,0);
	Ks=string(KEY_LEN,0);
	for (int i = 0; i < KEY_LEN; i++)
	{
		Kt[i] = rand();
		Ks[i] = rand();
	}

	// send PK to server

	return 0;
}
int UDSSE_Setup_Server()
{
	// EDB EDB_cache

	return 0;

}

// Search Part
int UDSSE_Search_Client(pairing_t &pairing, int sfd, string omega,string Ks)
{
	if (ldb.count(omega) == 0)
	{
		return -1;
	}
	LDB_ENTRY *entry=&ldb[omega];
	MSK_S *mskR = new MSK_S(*(entry->msk));
	SRE_KRev(pairing, mskR, entry->D);
	string Komega=PRF(Ks,omega);


	// send (msk_R,Komega/tkn,ST,c) to server

	return 0;
}
int UDSSE_Search_Server(pairing_t &pairing, int sfd,MSK_S *mskR ,string Komega, string ST, int c, string pk)
{
	vector<element_t> Res_tag;
	vector<string> Res_plain; //{tag,ct} 集合
	for (long long i = 0; i <= c; i++)
	{
		string UT = HMAC_SHA256(Komega, ST);
		string stream = HMAC_MD5(Komega, ST);
		string plain(edb[UT].e);

		int len = plain.length();
		for (int i = 0; i < len; i++)
		{
			plain[i] = plain[i] ^ stream[i % HASH2_LENGTH];
		}
		Res_tag.push_back(edb[UT].tag);
		Res_plain.push_back(plain);
		ST = rsa_pub_encrypt(ST, pk);
	}
	// 此时得到 {(tag,ct),...}

	// 解密
	vector<element_t> Res_tag_dec;
	vector<string> Res_plain_dec;
	element_t cipher;
	element_t plain;
	element_init_GT(plain,pairing);
	element_init_GT(cipher,pairing);
	int m = Res_plain.size();
	unsigned char tempbuf[1024];
	for (int i = 0; i < m; i++)
	{
		element_from_bytes(cipher,(unsigned char*)Res_plain[i].c_str());
		// byte -> element


		int mark=SRE_Dec(pairing,mskR,cipher,Res_tag[i],plain);
		if(mark==SRE_DEC_SUCCESS)
		{

			int len=element_to_bytes(tempbuf,plain);
			string tempstr(tempbuf,len);
			Res_tag_dec.push_back(Res_tag[i]);
			Res_plain_dec.push_back(tempstr);
		}
		else if(mark==SRE_DEC_FAIL)
		{
			continue;
		}
	}
	// 此时得到 Res,返回给client.

	return 0;
}





//  Update Part
int UDSSE_Update_Client(pairing_t &pairing, int sfd,OP_TYPE op,string Ks,string Ktag,string omega, string ind)
{
	if (ldb.count(omega) == 0)
	{
		//不存在则创建
		LDB_ENTRY entry;
		SRE_KGen(pairing, entry.msk, lambda_, b_, h_, 1);
		entry.D=new vector<string>();
		ldb.insert(pair<string,LDB_ENTRY>(omega,entry));
	}
	// 计算PRF值
	// unsigned char PRF_Val[HASH_VALUE_LENGTH];
	// int inputLen = strlen(omega) + strlen(ind);
	// char *inputText = new char[inputLen + 1];
	// PRF(PRF_Val, Kt, KEY_LEN, inputText, inputLen);
	string tagBytes=PRF(Ktag,omega+ind);

	// 计算tag并转化到ECC上
	element_t tag;
	element_init_G1(tag, pairing);
	element_from_hash(tag, tagBytes, HASH_VALUE_LENGTH);
	element_t *tagList;
	tagList = &tag;

	// DEL OP or Other OP
	if (op == OP_DEL)
	{
		ldb[omega].D.push_back(tag);
	}
	else if (op != OP_ADD && op != OP_DEL)
	{
		printf("NOT SUPPORTED OPERATION ! ");
	}

	// ADD OP
	if (op == OP_ADD)
	{
		// client 计算密文
		element_t plain;
		element_init_GT(plain, pairing);
		element_from_hash(plain, ind, ind.size());
		CT_S *ct;
		SRE_Enc(pairing, ldb[omega].msk, plain, tagList, ct);


		// ct to bytes

		
		// client & server
		std::string Komega;
		std::string ST;
		std::string UT;
		std::string stream;
		HMAC_SHA256(Komega, ST, UT);
		HMAC_MD5(Komega, ST, stream);
		int len = plain.length();
		std::string cipher(len, '\0');
		for (int i = 0; i < len; i++)
		{
			cipher[i] = plain[i] ^ stream[i % MD5_HASH_LENGTH];
		}

		// send cipher
	}
	return 0;
}
// std::string &plain
int UDSSE_Update_Server()
{
}




// Update Key Part

int UDSSE_UpdateKey(pairing_t &pairing, int sfd, string omega)
{
	mapValPair *temp = &(MAP[omega]);
	if (temp == nullptr)
	{
		SRE_KGen(pairing, temp->msk, lambda_, b_, h_, d_);
		temp->i = 0;
		temp->D.clear();
	}
	token *token;
	UPE_UPDATE_SK(pairing, temp->msk->pp, temp->msk->sk, token);

	// send token
	unsigned char buf[1024];
	int len;
	len = element_to_bytes(buf, token->d_alpha);
	write(sfd, buf, len);
	write(sfd, " ", 1);
	len = element_to_bytes(buf, token->galpha);
	write(sfd, buf, len);
}
