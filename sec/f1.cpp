/*-------------------------------------------------------------------
* Example algorithms f1, f1*, f2, f3, f4, f5, f5*
*-------------------------------------------------------------------
*
* A sample implementation of the example 3GPP authentication and
* key agreement functions f1, f1*, f2, f3, f4, f5 and f5*. This is
* a byte-oriented implementation of the functions, and of the block
* cipher kernel function Rijndael.
*
* This has been coded for clarity, not necessarily for efficiency.
*
* The functions f2, f3, f4 and f5 share the same inputs and have
* been coded together as a single function. f1, f1* and f5* are
* all coded separately.
*
*-----------------------------------------------------------------*/
#include"sha256.h"
#include"snow_3g.h"
#include"../s1ap_common.h"
#include"f1.h"
#include<stdio.h>
typedef unsigned char u8;
/*--------- Operator Variant Algorithm Configuration Field --------*/
/*------- Insert your value of OP here -------*/
u8 OP[16] = { 0x63, 0xbf, 0xa5, 0x0e, 0xe6, 0x52, 0x33, 0x65,
0xff, 0x14, 0xc1, 0xf4, 0x5f, 0x88, 0x73, 0x7d };
/*------- Insert your value of OP here -------*/
/*--------------------------- prototypes --------------------------*/
void f1(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
	u8 mac_a[8]);
void f2345(u8 k[16], u8 rand[16],
	u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6]);
void f1star(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
	u8 mac_s[8]);
void f5star(u8 k[16], u8 rand[16],
	u8 ak[6]);
void ComputeOPc(u8 op_c[16]);
void RijndaelKeySchedule(u8 key[16]);
void RijndaelEncrypt(u8 input[16], u8 output[16]);
/*-------------------------------------------------------------------
* Algorithm f1
*-------------------------------------------------------------------
*
* Computes network authentication code MAC-A from key K, random
* challenge RAND, sequence number SQN and authentication management
* field AMF.
*
*-----------------------------------------------------------------*/
void f1(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
	u8 mac_a[8])
{
	u8 op_c[16];
	u8 temp[16];
	u8 in1[16];
	u8 out1[16];
	u8 rijndaelInput[16];
	u8 i;
	RijndaelKeySchedule(k);
	ComputeOPc(op_c);

	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);
	for (i = 0; i<6; i++)
	{
		in1[i] = sqn[i];
		in1[i + 8] = sqn[i];
	}
	for (i = 0; i<2; i++)
	{
		in1[i + 6] = amf[i];
		in1[i + 14] = amf[i];
	}
	/* XOR op_c and in1, rotate by r1=64, and XOR *
	* on the constant c1 (which is all zeroes) */
	for (i = 0; i<16; i++)
		rijndaelInput[(i + 8) % 16] = in1[i] ^ op_c[i];
	/* XOR on the value temp computed before */
	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= temp[i];

	RijndaelEncrypt(rijndaelInput, out1);
	for (i = 0; i<16; i++)
		out1[i] ^= op_c[i];
	for (i = 0; i<8; i++)
		mac_a[i] = out1[i];

	return;
} /* end of function f1 */

  /*-------------------------------------------------------------------
  * Algorithms f2-f5
  *-------------------------------------------------------------------
  *
  * Takes key K and random challenge RAND, and returns response RES,
  * confidentiality key CK, integrity key IK and anonymity key AK.
  *
  *-----------------------------------------------------------------*/
void f2345(u8 k[16], u8 rand[16],
	u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6])
{
	u8 op_c[16];
	u8 temp[16];
	u8 out[16];
	u8 rijndaelInput[16];
	u8 i;
	RijndaelKeySchedule(k);
	ComputeOPc(op_c);
	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);
	/* To obtain output block OUT2: XOR OPc and TEMP, *
	* rotate by r2=0, and XOR on the constant c2 (which *
	* is all zeroes except that the last bit is 1). */
	for (i = 0; i<16; i++)
		rijndaelInput[i] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 1;
	RijndaelEncrypt(rijndaelInput, out);
	for (i = 0; i<16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i<8; i++)
		res[i] = out[i + 8];
	for (i = 0; i<6; i++)
		ak[i] = out[i];
	/* To obtain output block OUT3: XOR OPc and TEMP, *
	* rotate by r3=32, and XOR on the constant c3 (which *
	* is all zeroes except that the next to last bit is 1). */
	for (i = 0; i<16; i++)
		rijndaelInput[(i + 12) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 2;
	RijndaelEncrypt(rijndaelInput, out);
	for (i = 0; i<16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i<16; i++)
		ck[i] = out[i];
	/* To obtain output block OUT4: XOR OPc and TEMP, *
	* rotate by r4=64, and XOR on the constant c4 (which *
	* is all zeroes except that the 2nd from last bit is 1). */
	for (i = 0; i<16; i++)
		rijndaelInput[(i + 8) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 4;
	RijndaelEncrypt(rijndaelInput, out);
	for (i = 0; i<16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i<16; i++)
		ik[i] = out[i];

	return;
} /* end of function f2345 */

  /*-------------------------------------------------------------------
  * Algorithm f1*
  *-------------------------------------------------------------------
  *
  * Computes resynch authentication code MAC-S from key K, random
  * challenge RAND, sequence number SQN and authentication management
  * field AMF.
  *
  *-----------------------------------------------------------------*/
void f1star(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
	u8 mac_s[8])
{
	u8 op_c[16];
	u8 temp[16];
	u8 in1[16];
	u8 out1[16];
	u8 rijndaelInput[16];
	u8 i;
	RijndaelKeySchedule(k);
	ComputeOPc(op_c);
	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);
	for (i = 0; i<6; i++)
	{
		in1[i] = sqn[i];
		in1[i + 8] = sqn[i];
	}
	for (i = 0; i<2; i++)
	{
		in1[i + 6] = amf[i];
		in1[i + 14] = amf[i];
	}
	/* XOR op_c and in1, rotate by r1=64, and XOR *
	* on the constant c1 (which is all zeroes) */
	for (i = 0; i<16; i++)
		rijndaelInput[(i + 8) % 16] = in1[i] ^ op_c[i];
	/* XOR on the value temp computed before */
	for (i = 0; i<16; i++)
		rijndaelInput[i] ^= temp[i];

	RijndaelEncrypt(rijndaelInput, out1);
	for (i = 0; i<16; i++)
		out1[i] ^= op_c[i];
	for (i = 0; i<8; i++)
		mac_s[i] = out1[i + 8];
	return;
} /* end of function f1star */

  /*-------------------------------------------------------------------
  * Algorithm f5*
  *-------------------------------------------------------------------
  *
  * Takes key K and random challenge RAND, and returns resynch
  * anonymity key AK.
  *
  *-----------------------------------------------------------------*/
void f5star(u8 k[16], u8 rand[16],
	u8 ak[6])
{
	u8 op_c[16];
	u8 temp[16];
	u8 out[16];
	u8 rijndaelInput[16];
	u8 i;
	RijndaelKeySchedule(k);
	ComputeOPc(op_c);
	for (i = 0; i<16; i++)
		rijndaelInput[i] = rand[i] ^ op_c[i];
	RijndaelEncrypt(rijndaelInput, temp);
	/* To obtain output block OUT5: XOR OPc and TEMP, *
	* rotate by r5=96, and XOR on the constant c5 (which *
	* is all zeroes except that the 3rd from last bit is 1). */
	for (i = 0; i<16; i++)
		rijndaelInput[(i + 4) % 16] = temp[i] ^ op_c[i];
	rijndaelInput[15] ^= 8;
	RijndaelEncrypt(rijndaelInput, out);
	for (i = 0; i<16; i++)
		out[i] ^= op_c[i];
	for (i = 0; i<6; i++)
		ak[i] = out[i];
	return;
} /* end of function f5star */

  /*-------------------------------------------------------------------
  * Function to compute OPc from OP and K. Assumes key schedule has
  already been performed.
  *-----------------------------------------------------------------*/
void ComputeOPc(u8 op_c[16])
{
	int i;
	char s[]="b0f81a46608e80b22a3023e00a396fd7";
	for(i=0;i<16;i++){
		op_c[i]=c2u(s[i*2])*16+c2u(s[i*2+1]);
	}
/*u8 i;

 RijndaelEncrypt( OP, op_c );
 for (i=0; i<16; i++)
 op_c[i] ^= OP[i];
*/
} /* end of function ComputeOPc */
  /*-------------------- Rijndael round subkeys ---------------------*/
u8 roundKeys[11][4][4];
/*--------------------- Rijndael S box table ----------------------*/
u8 S[256] = {
	99,124,119,123,242,107,111,197, 48, 1,103, 43,254,215,171,118,
	202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
	183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
	4,199, 35,195, 24,150, 5,154, 7, 18,128,226,235, 39,178,117,
	9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
	83,209, 0,237, 32,252,177, 91,106,203,190, 57, 74, 76, 88,207,
	208,239,170,251, 67, 77, 51,133, 69,249, 2,127, 80, 60,159,168,
	81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
	205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
	96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
	224, 50, 58, 10, 73, 6, 36, 92,194,211,172, 98,145,149,228,121,
	231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174, 8,
	186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
	112, 62,181,102, 72, 3,246, 14, 97, 53, 87,185,134,193, 29,158,
	225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
	140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22,
};
/*------- This array does the multiplication by x in GF(2^8) ------*/
u8 Xtime[256] = {
	0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30,
	32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62,
	64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94,
	96, 98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
	128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
	160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
	192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
	224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
	27, 25, 31, 29, 19, 17, 23, 21, 11, 9, 15, 13, 3, 1, 7, 5,
	59, 57, 63, 61, 51, 49, 55, 53, 43, 41, 47, 45, 35, 33, 39, 37,
	91, 89, 95, 93, 83, 81, 87, 85, 75, 73, 79, 77, 67, 65, 71, 69,
	123,121,127,125,115,113,119,117,107,105,111,109, 99, 97,103,101,
	155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
	187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
	219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
	251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229
};
/*-------------------------------------------------------------------
* Rijndael key schedule function. Takes 16-byte key and creates
* all Rijndael's internal subkeys ready for encryption.
*-----------------------------------------------------------------*/
void RijndaelKeySchedule(u8 key[16])
{
	u8 roundConst;
	int i, j;
	/* first round key equals key */
	for (i = 0; i<16; i++)
		roundKeys[0][i & 0x03][i >> 2] = key[i];
	roundConst = 1;
	/* now calculate round keys */
	for (i = 1; i<11; i++)
	{
		roundKeys[i][0][0] = S[roundKeys[i - 1][1][3]]
			^ roundKeys[i - 1][0][0] ^ roundConst;
		roundKeys[i][1][0] = S[roundKeys[i - 1][2][3]]
			^ roundKeys[i - 1][1][0];
		roundKeys[i][2][0] = S[roundKeys[i - 1][3][3]]
			^ roundKeys[i - 1][2][0];
		roundKeys[i][3][0] = S[roundKeys[i - 1][0][3]]
			^ roundKeys[i - 1][3][0];
		for (j = 0; j<4; j++)
		{
			roundKeys[i][j][1] = roundKeys[i - 1][j][1] ^ roundKeys[i][j][0];
			roundKeys[i][j][2] = roundKeys[i - 1][j][2] ^ roundKeys[i][j][1];
			roundKeys[i][j][3] = roundKeys[i - 1][j][3] ^ roundKeys[i][j][2];
		}
		/* update round constant */
		roundConst = Xtime[roundConst];
	}
	return;
} /* end of function RijndaelKeySchedule */
  /* Round key addition function */
void KeyAdd(u8 state[4][4], u8 roundKeys[11][4][4], int round)
{
	int i, j;
	for (i = 0; i<4; i++)
		for (j = 0; j<4; j++)
			state[i][j] ^= roundKeys[round][i][j];
	return;
}
/* Byte substitution transformation */
int ByteSub(u8 state[4][4])
{
	int i, j;
	for (i = 0; i<4; i++)
		for (j = 0; j<4; j++)
			state[i][j] = S[state[i][j]];

	return 0;
}
/* Row shift transformation */
void ShiftRow(u8 state[4][4])
{
	u8 temp;
	/* left rotate row 1 by 1 */
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;
	/* left rotate row 2 by 2 */
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;
	/* left rotate row 3 by 3 */
	temp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
	return;
}
/* MixColumn transformation*/
void MixColumn(u8 state[4][4])
{
	u8 temp, tmp, tmp0;
	int i;
	/* do one column at a time */
	for (i = 0; i<4; i++)
	{
		temp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		tmp0 = state[0][i];
		/* Xtime array does multiply by x in GF2^8 */
		tmp = Xtime[state[0][i] ^ state[1][i]];
		state[0][i] ^= temp ^ tmp;
		tmp = Xtime[state[1][i] ^ state[2][i]];
		state[1][i] ^= temp ^ tmp;
		tmp = Xtime[state[2][i] ^ state[3][i]];
		state[2][i] ^= temp ^ tmp;
		tmp = Xtime[state[3][i] ^ tmp0];
		state[3][i] ^= temp ^ tmp;
	}
	return;
}
/*-------------------------------------------------------------------
* Rijndael encryption function. Takes 16-byte input and creates
* 16-byte output (using round keys already derived from 16-byte
* key).
*-----------------------------------------------------------------*/
void RijndaelEncrypt(u8 input[16], u8 output[16])
{
	u8 state[4][4];
	int i, r;
	/* initialise state array from input byte string */
	for (i = 0; i<16; i++)
		state[i & 0x3][i >> 2] = input[i];
	/* add first round_key */
	KeyAdd(state, roundKeys, 0);

	/* do lots of full rounds */
	for (r = 1; r <= 9; r++)
	{
		ByteSub(state);
		ShiftRow(state);
		MixColumn(state);
		KeyAdd(state, roundKeys, r);
	}
	/* final round */
	ByteSub(state);
	ShiftRow(state);
	KeyAdd(state, roundKeys, r);
	/* produce output byte string from state array */
	for (i = 0; i<16; i++)
	{
		output[i] = state[i & 0x3][i >> 2];
	}
	return;
} /* end of function RijndaelEncrypt */
void setinput_k_asme(uint8_t* input,u8* temp){
	input[0]=0x10;

	input[1]=0x00;
	input[2]=0xf1;
	input[3]=0x10;

	input[4]=0x00;
	input[5]=0x03;

	input[6]=temp[0];
	input[7]=temp[1];
	input[8]=temp[2];
	input[9]=temp[3];
	input[10]=temp[4];
	input[11]=temp[5];

	input[12]=0x00;
	input[13]=0x06;
}
void setinput_k_nasint(uint8_t* input,int int_al){
	input[0]=0x15;

	input[1]=0x02;

	input[2]=0x00;
	input[3]=0x01;

	input[4]=int_al;

	input[5]=0x00;
	input[6]=0x01;
}
void setinput_k_nasenc(uint8_t* input,int enc_al){
	input[0]=0x15;
	
	input[1]=0x01;

	input[2]=0x00;
	input[3]=0x01;

	input[4]=enc_al;

	input[5]=0x00;
	input[6]=0x01;
}
void setinput_k_enb(uint8_t uplink_NAS_count,uint8_t* input){
	input[0]=0x11;
	input[1]=0x00; input[2]=0x00; input[3]=0x00; input[4]=uplink_NAS_count; //TODO: this field is for uplink count, check what it is and fix this
	printf("uplink_NAS_count=%d\n",uplink_NAS_count);
	input[5]=0x00;input[6]=0x04;
}
void setinput_Next_HOP(ue_ctx_t* ue, uint8_t* input){
	input[0]=0x12;
	memcpy(&input[1],ue->sec.k_enb,32);
	input[33]=0x00;	input[34]=0x20;	
}
void setinput_k_enb_star(uint8_t *input){
	input[0]=0x13;
	input[1]=0x00; input[2]=0x0a;	//PHY Cell ID
	input[3]=0x00; input[4]=0x02;	//length of PHY Cell ID
	input[5]=0x0c; input[6]=0x1c;	//EARFCN-DL = 3100
	input[7]=0x00; input[8]=0x02;	//length of EARFCN-DL
}
void init_k_int_enc(u8 k_asme[32],u8 k_nasint[32],u8 k_nasenc[32],int int_al,int enc_al){
	uint8_t input[7];
	if(enc_al!=0){
		setinput_k_nasenc(input,enc_al);
		sha256_hmac(k_asme,32,input,7,k_nasenc,0);
	}
	if(int_al!=0){
		setinput_k_nasint(input,int_al);
		sha256_hmac(k_asme,32,input,7,k_nasint,0);
	}
int i;	 printf("k_nasint: ");
for(i=0;i<32;i++)printf("%02x",k_nasint[i]);
printf("\n");
}
uint8_t* do_EIA1(uint8_t k_nasint[32],uint8_t* message,int len,int int_al,uint32_t* dl_count){
	return snow3g_f9(&k_nasint[16],(*dl_count)++,0,1,message,len*8);
}
void get_res_autn_k_asme(u8 res[8],u8 autn[16],u8 k_asme[32],u8 rand[16],u8 sqn[6]){
	/*******************************************************************
			Authentication Request (Calculated by HSS)
	*******************************************************************/
	int i=0;
	char k_c[]="000102030405060708090a0b0c0d0e0f";
	char amf_c[]="8000";
	char sqn_c[]="000000000000";
	u8 k[16],amf[2],mac_a[8];
	u8 ck[16],ik[16],ak[6],sqn_xor_ak[6];

	for(i=0;i<16;i++){
		k[i]=c2u(k_c[2*i])*16+c2u(k_c[2*i+1]);
		if(i<2){
			amf[i]=c2u(amf_c[2*i])*16+c2u(amf_c[2*i+1]);
		}
	}
	printf("++++++++++++++++++++++++++++++++++++++++\n");
	printf("sqn: ");
	for(i = 0;i<6;i++)
		printf("%02x",sqn[i]);
	printf("\n++++++++++++++++++++++++++++++++++++++++\n");
	
	
	// calculate res ck ik ak
	f2345(k,rand,res,ck,ik,ak);

	for(i=0;i<6;i++)
		sqn_xor_ak[i]=sqn[i]^ak[i];
	// calculate sqn
/*	u8 sqn[6];
	u8 temp[6];
	char temp_c[]="da3569e36b7f";
	printf("sqn: ");
	for(i=0;i<6;i++){
		temp[i]=c2u(temp_c[i*2])*16+c2u(temp_c[i*2+1]);
		sqn[i]=temp[i]^ak[i];
		printf("%02x",sqn[i]);
		sqn_xor_ak[i]=temp[i];
	}
	printf("\n");*/

	// calculate AUTN's mac_a
	f1(k,rand,sqn,amf,mac_a);

	// combine SQN ^ AK and amf and mac_a here will ommit AUTN

	for(i=0;i<6;i++)
		autn[i]=sqn[i]^ak[i];
	for(i=0;i<2;i++)
		autn[6+i]=amf[i];
	for(i=0;i<8;i++)
		autn[8+i]=mac_a[i];

	// derive K_asme
	uint8_t ckik[32],input[14];
	for(i=0;i<16;i++)
		ckik[i]=ck[i];
	for(i=0;i<16;i++)
		ckik[i+16]=ik[i];
	setinput_k_asme(input,sqn_xor_ak);
	sha256_hmac(ckik,32,input,14,k_asme,0);
printf("k_asme : ");
for(i=0;i<32;i++) printf("%02x",k_asme[i]);
printf("\n");

}
void resync(uint8_t* sqn_ms_xor_ak,uint8_t* rand,uint8_t* sqn){
	char k_c[]="000102030405060708090a0b0c0d0e0f";
	char mac_s_c[]="2dbf14525481ffd0";
	u8 k[16];
	u8 ak[6],amf[2]={0x80,0x00},mac_s[8];
	int i;
	for(i=0;i<16;i++)
		k[i]=c2u(k_c[i*2])*16+c2u(k_c[i*2+1]);
	f5star(k,rand,ak);
	
	for(i=0;i<6;i++)
		sqn[i]=sqn_ms_xor_ak[i]^ak[i];
printf("before :%02x\n",sqn[5]);
if(sqn[5]>=0xe0)
	sqn[4]++;
i=4;
while(sqn[i]==0)//TODO: i>0
	sqn[--i]++;
sqn[5]+=0x20;
printf("after : %02x\n",sqn[5]);

	f1star(k, rand, sqn, amf, mac_s);

	printf("mac: \n");
	for(i=0;i<8;i++) printf("%02x",mac_s[i]);
	printf("\n%s\n",mac_s_c);

	printf("sqn: \n");
	for(i=0;i<6;i++) printf("%02x",sqn[i]);
	printf("\n");
}
void c2us(u8* u,char* uc,int len){
	int i;
	for(i=0;i<len;i++) u[i]=c2u(uc[i*2])*16+c2u(uc[i*2+1]);
}
//TODO: add prefix "sec" for every security related function? sec_get_k_enb
void get_k_enb(ue_ctx_t* ue,uint8_t* k_enb){
	uint8_t input[7];
	setinput_k_enb(ue->sec.ul_count,input);
	printf("Computing Kenb----------\n");
	printf("k_asme: %x %x %x\n",ue->sec.k_asme[0],ue->sec.k_asme[1],ue->sec.k_asme[2]);
	sha256_hmac(ue->sec.k_asme,32,input,7,k_enb,0);
	printf("k_enb: %x %x %x\n",k_enb[0],k_enb[1],k_enb[2]);
}
void get_Next_Hop(ue_ctx_t* ue,uint8_t* NH){
	uint8_t input[34];
	setinput_Next_HOP(ue, input);
	printf("Computing Next HOP----------\n");
	printf("k_asme: %x %x %x\n",ue->sec.k_asme[0],ue->sec.k_asme[1],ue->sec.k_asme[2]);
	printf("k_enb: %x %x %x\n",ue->sec.k_enb[0],ue->sec.k_enb[1],ue->sec.k_enb[2]);
	sha256_hmac(ue->sec.k_asme,32,input,35,NH,0);
	printf("NH: %x %x %x\n",NH[0],NH[1],NH[2]);
}
void get_k_enb_star(ue_ctx_t* ue,uint8_t* k_enb_star){
	uint8_t input[9];
	setinput_k_enb_star(input);
	printf("Computing Kenb*----------\n");
	printf("ue->sec.k_enb:%x %x %x\n",ue->sec.k_enb[0],ue->sec.k_enb[1],ue->sec.k_enb[2]);
	sha256_hmac(ue->sec.k_enb,32,input,9,k_enb_star,0);
	printf("k_enb*:%x %x %x\n",k_enb_star[0],k_enb_star[1],k_enb_star[2]);
}
/*
int main(){
	uint8_t input[100];
	setinput_k_enb(input);
	char k_asme_c[]="cd841ed20dc6fb5b0c4ca833bf7629346f3d3990cab9d93177877bf20cde5a5d";
	uint8_t k_asme[200];
	uint8_t k_enb[32];
	c2us(k_asme,k_asme_c,32);
	int i;
	printf("k_asme:\n");
	for(i=0;i<32;i++) printf("%02x",k_asme[i]);
	printf("\n%s\n",k_asme_c);
	sha256_hmac(k_asme,32,input,7,k_enb,0);
	printf("k_enb:\n");
	for(i=0;i<32;i++) printf("%02x",k_enb[i]);
	printf("\n");
}*/
/*
int main(){
	char sqn_ms_xor_ak_c[]="f86d8b8bf53d";
	
	u8 sqn[6];
	u8 amf[2]={0x80,0x00},sqn_ms_xor_ak[6],rand[16];
	u8 res[8],k_asme[32],autn[16];
	int i;
	for(i=0;i<6;i++)
		sqn_ms_xor_ak[i]=c2u(sqn_ms_xor_ak_c[i*2])*16+c2u(sqn_ms_xor_ak_c[i*2+1]);
	for(i=0;i<16;i++)
		rand[i]=c2u(rand_c[i*2])*16+c2u(rand_c[i*2+1]);
	resync(sqn_ms_xor_ak,rand,sqn);
	
	get_res_autn_k_asme(res,autn,k_asme,rand,sqn);
printf("autn:");
for(i=0;i<16;i++)printf("%02x",autn[i]);
printf("\n");
}*/
/*
int main(){
	int i,enc_al=1,int_al=1;
	u8 res[8],autn[16],k_asme[32],rand[16],sqn[6];
	char rand_c[]="07160400000000000716040000000000";
	for(i=0;i<16;i++) rand[i]=c2u(rand_c[i*2])*16+c2u(rand_c[i*2+1]);
	get_res_autn_k_asme(res,autn,k_asme,rand);

	printf("res: ");
	for(i=0;i<8;i++) printf("%02x",res[i]);
	printf("\n");
	printf("autn: ");
	for(i=0;i<16;i++) printf("%02x",autn[i]);
	printf("\n");
	printf("k_asme: ");
	for(i=0;i<32;i++) printf("%02x",k_asme[i]);
	printf("\n");

			 //EIA (EPS Integrity Algorithm)                    
	
	
	uint8_t input[14],k_nasint[32],k_nasenc[32];


	// derive K_nasenc
	char message_c[]="00075d010005e060c04070";
	uint8_t message[100],*ss,out[10];
	for(i=1;i<11;i++) message[i-1]=c2u(message_c[i*2])*16+c2u(message_c[i*2+1]);
	setinput_k_nasenc(input,enc_al);
	sha256_hmac(k_asme,32,input,7,k_nasenc,0);
	printf("k_nasenc: ");
	for(i=0;i<32;i++) printf("%02x",k_nasenc[i]);
	printf("\n");
	encryption_eea1(&k_nasenc[16],0,0,1,message,80,out);
	printf("out: ");
	for(i=0;i<10;i++) printf("%02x",out[i]);
	printf("\n");

	// derive K_nasint
	setinput_k_nasint(input,int_al);
	sha256_hmac(k_asme,32,input,7,k_nasint,0);
	printf("k_nasint: ");
	for(i=0;i<32;i++) printf("%02x",k_nasint[i]);
	printf("\n");

	// derive MAC
	for(i=0;i<11;i++) message[i]=c2u(message_c[i*2])*16+c2u(message_c[i*2+1]);
	ss=snow3g_f9(&k_nasint[16],0,0,1,message,88);
	printf("MAC(integrity): ");
	for(i=0;i<4;i++) printf("%02x",ss[i]);
	printf("\n");

	char message_c2[]="01075502";
	c2us(message,message_c2,4);
	ss=snow3g_f9(&k_nasint[16],1,0,1,message,32);
	for(i=0;i<4;i++)printf("%02x",ss[i]);
	printf("\n");
}*/
/*
int main(){
	char buf[]="0307420249062000f1100001003d5201c10109100361706e0b546573744e6574776f726b0501c0a8c8095e029797271b80802110030000108106c0a80764830600000000000d04c0a80764500bf600f110800001ce48315a5312640101";
	char k_nasint[]="5e1cd3af2f764843dc82eaee83ba78ec25e1259353cfce636002ea1c34d6c9bd";
	uint8_t ubuf[93],uknasint[32];
	uint8_t* eia;
	c2u(ubuf,buf,93);
	printf("ubuf: ");
	for(int i=0;i<93;i++){
		if(i%16==0) printf("\n");
		printf("%02x",ubuf[i]);
	}
	printf("\n\nknasint: ");
	c2u(uknasint,k_nasint,32);
	for(int i=0;i<32;i++){
		if(i%16==0) printf("\n");
		printf("%02x",uknasint[i]);
	}
	uint32_t s=3;
	eia=do_EIA1(uknasint,ubuf,93,1,&s);
	printf("\neia:\n");
	int i;
	for(i=0;i<4;i++)
		printf("%02x",eia[i]);
}*/
