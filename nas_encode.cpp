#include<stdio.h>
#include<stdlib.h>
#include<memory.h>
#include<pthread.h>
#include"sec/f1.h"
#include"nas_encode.h"
nas_encode* nas_encode::m_instance=NULL;
pthread_mutex_t nas_encode_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

nas_encode::nas_encode(){

}
nas_encode* nas_encode::get_instance(){
	pthread_mutex_lock(&nas_encode_instance_mutex);
	if(m_instance==NULL){
		m_instance=new nas_encode();
	}
	pthread_mutex_unlock(&nas_encode_instance_mutex);
	return m_instance;
}
int nas_encode::encode_UE_security_capability(uint8_t* buf,ue_ctx_t* ue){
//TODO: distinguish what to write here
	uint8_t temp=0;
	int i;
	buf[0]=5;	//len
	temp=ue->prop.msg_type.ar.ue_cap.eea[0];
	for(i=1;i<8;i++){
		temp<<=1;
		temp+=ue->prop.msg_type.ar.ue_cap.eea[i];
	}
	buf[1]=temp;

	temp=ue->prop.msg_type.ar.ue_cap.eia[0];
	for(i=1;i<8;i++){
		temp<<=1;
		temp+=ue->prop.msg_type.ar.ue_cap.eia[i];
	}
	buf[2]=temp;

	temp=ue->prop.msg_type.ar.ue_cap.uea[0];
	for(i=1;i<8;i++){
		temp<<=1;
		temp+=ue->prop.msg_type.ar.ue_cap.uea[i];
	}
	buf[3]=temp;


	temp=ue->prop.msg_type.ar.ue_cap.uia[1];
	for(i=2;i<8;i++){
		temp<<=1;
		temp+=ue->prop.msg_type.ar.ue_cap.uia[i];
	}
	buf[4]=temp;

	temp=ue->prop.msg_type.ar.ms_net_cap.gea[1];
	for(i=2;i<8;i++){
		temp<<=1;
		temp+=ue->prop.msg_type.ar.ms_net_cap.gea[i];
	}
	buf[5]=temp;
	return buf[0]+1;
}
int nas_encode::encode_Identity_Request_message_IMSI(uint8_t* buf){
	printf("Send Message type : Identity Request Message IMSI\n");
	buf[0]=0x03;	//len
	buf[1]=0x07;	//Plain&EMM
	buf[2]=0x55;	//Message Type : Identity Request
	buf[3]=0x01;	//Idnetity type 2 : IMSI
	return 4;
}
int nas_encode::encode_Authentication_Request(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : Authentication Request\n");
	int i;
	uint8_t autn[16];
	get_res_autn_k_asme(ue->sec.res,autn,ue->sec.k_asme,ue->sec.rand,ue->sec.sqn);

	printf("res: ");
	for(i=0;i<8;i++) printf("%02x",ue->sec.res[i]);
	printf("\n");

	buf[0]=0x24;	//len
	buf[1]=0x07;	//Plain&EMM
	buf[2]=0x52;	//Authentication Request
	buf[3]=0x00;	//??? ASME
	
	for(i=0;i<16;i++) buf[i+4]=ue->sec.rand[i];

	buf[20]=0x10;	//len of autn
	for(i=0;i<16;i++) buf[i+21]=autn[i];
	return 0x25;
}
int nas_encode::encode_Security_Mode_Command(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : Security Mode Command\n");
	uint8_t* ss;
	int len=0;
	buf[1]=0x37;	//Security & EMM

	buf[6]=ue->sec.dl_count;
	buf[7]=0x07;	//plain&EMM
	buf[8]=0x5d;	//Security Mode Command
	buf[9]=((ue->sec.enc_al)<<4)+((ue->sec.int_al));	//EIA&EEA
	buf[10]=0x00;	//TSC& key set id
	len+=encode_UE_security_capability(&buf[11],ue);

	buf[0]=10+len;	//len
	//TODO: len is variable

	ss=do_EIA1(ue->sec.k_nasint,&buf[6],5+len,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	return buf[0]+1;
}
int nas_encode::encode_ESM_Information_Request(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : ESM Information Request\n");
	uint8_t* ss;
	int len=0;
	buf[1]=0x27;	//Integrity and Ciphered

	buf[6]=ue->sec.dl_count;
	buf[7]=0x02;	//ESM
	buf[8]=ue->prop.msg_type.ar.pdn_con_request.procedure_transaction_id;
	buf[9]=0xd9;	//ESM information_Request

	buf[0]=9;	//len

	ss=do_EIA1(ue->sec.k_nasint,&buf[6],4,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	return buf[0]+1;
	
}
int nas_encode::encode_EMM_Information_Request(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : EMM Information Request");
	uint8_t* ss;
	int len=0;
	buf[1]=0x27;
	
	buf[6]=ue->sec.dl_count;
	buf[7]=0x07;
	buf[8]=0x61;	//EMM information
	buf[9]=0x46;	//IE: Time Zone
	buf[10]=0x23;	//GMT +8
	buf[11]=0x49;	//IE: Daylight Saving Time
	buf[12]=0x01;	//len
	buf[13]=0x00;	//no DST

	buf[0]=0x0d;
	ss=do_EIA1(ue->sec.k_nasint,&buf[6],8,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	return buf[0]+1;
}
int nas_encode::encode_Activate_default_context_request(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
//TODO: not checked and not used function
//TODO:default: ebi=5 should it be general to all ebi?
/*
	buf[0]=0x52;
	buf[1]=ue->prop.pdn_con_request.procedure_transaction_id;
	buf[2]=0xc1;	//id-Activate default context request
	buf[3]=0x01;	//qCI len
	//TODO: qCI should be set by the data send from spgw? 
	buf[4]=0x09;	//qCI
	buf[5]=ue->prop.apn_len;
	memcpy(&buf[6],ue->prop.apn_name,buf[5]);
	len=buf[5]+1;
	buf[5+len]=0x05;	//PDN len
	buf[6+len]=0x01;	//IPv4
	memcpy(&buf[7+len],ue->erab[5].pdn_ipv4,4);
	buf[11+len]=0x5e;	//ID: apn aggregate maximum bit rate
	buf[12+len]=0x02;	//len
	buf[13+len]=0x97;	//apn-ambr dl
	buf[14+len]=0x97;	//apn-ambr ul
	buf[15+len]=0x27;	//ID: PCO
	buf[16+len]=27;		//PCO len
	buf[17+len]=0x80;	//<1> ext <xxxx> <000> PPP for use with IP PDP type or IP PDN type
	buf[18+len]=0x80; buf[19+len]=0x21;	//ID-IPCP
	buf[20+len]=0x10;	//len
	buf[21+len]=0x03;	//Nak
	buf[22+len]=0x00;	//Identifier
	buf[23+len]=0x10;	//len
	buf[24+len]=0x81;	//Primary DNS Server IP
	buf[25+len]=0x06;	//len
	buf[26+len]=192; buf[27+len]=168; buf[28+len]=7; buf[29+len]=100;//ip
	buf[30+len]=0x83;	//Secondary DNS Server IP
	buf[31+len]=0x06;	//len
	memset(&buf[32+len],0,4);//ip
	buf[36+len]=0x00; buf[37+len]=0x0d;	//ID-DNS Server IPv4
	buf[38+len]=0x04;	//len
	memcpy(&buf[39+len],&buf[26+len],4);	//IP
	return 42+len;
*/
	int c_len=61; char c[]="5201c10109100361706e0b546573744e6574776f726b0501c0a8c8095e029797271b80802110030000108106c0a80764830600000000000d04c0a80764";
	//int c_len=70; char c[] = "5211c10109100361706e0b546573744e6574776f726b0501c0a8c8075e02979727248080211001000010810600000000830600000000000d04c0a80764000501020010020578";
	
	c2u(buf,c,c_len);
	return c_len;
}
int nas_encode::encode_EPS_ID_GUTI(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x50;	//id-guti
	buf[1]=0x0b;	//len
	buf[2]=0xf6;	//<1111>x <0>even <110>GUTI
	buf[3]=0x00; buf[4]=0xf1; buf[5]=0x10;
	buf[6]=0x80; buf[7]=0x00; //MMEGI
	buf[8]=0x01;	//MMEC
	memcpy(&buf[9],&ue->prop.msg_type.ar.eps_mobile_id.guti.m_tmsi,4);
	return 13;
}
int nas_encode::encode_Attach_Accept(uint8_t* buf,ue_ctx_t* ue){
	uint8_t* ss;
	int len=0;
	buf[1]=0x27;

	buf[6]=ue->sec.dl_count;
	buf[7]=0x07;
	buf[8]=0x42;	//Attach Accept
	buf[9]=0x02;	//Attach result:Combined EPS/IMSI attach
	buf[10]=0x49;	//GPRS Timer
	//TAI List
	//TODO: read file to write list here? Not neccessary when TAC is consecutive
	buf[11]=0x06;
	buf[12]=0x20;	//<0>spare <01>:TAC consecutive <00000>Num of element
	buf[13]=0x00; buf[14]=0xf1; buf[15]=0x10; //PLMN
	buf[16]=0x00; buf[17]=0x01; //TAC
	//TODO: len should be seperated to buf[18] and buf[19]
	buf[18]=0x00;
	len=buf[19]=encode_Activate_default_context_request(&buf[20],ue);
	len+=encode_EPS_ID_GUTI(&buf[20+len],ue);
	buf[20+len]=0x53;//EMM cause
	buf[21+len]=0x12;//CS domain not available
	buf[22+len]=0x64;//EPS network feature support
	buf[23+len]=0x01;
	buf[24+len]=0x01;

	buf[0]=24+len;
	ss=do_EIA1(ue->sec.k_nasint,&buf[6],19+len,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	printf("len: %d\nbuf:",19+len);
	int i=0;
	for(i=0;i<25+len;i++){
		if(i%16==0) printf("\n");
		printf("%02x",buf[i]);
	}

	return buf[0]+1;
}
/*
int main(){
	uint8_t sendbuf[300];
	ue_ctx_t ue;
	encode_Security_Mode_Command(sendbuf,ue);
	int i;
	for(i=0;i<
}*/
