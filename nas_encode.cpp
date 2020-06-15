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
int nas_encode::encode_GPRS_Timer(uint8_t* buf){
	int len=2;
	buf[0]=0x5a;	//Element ID
	buf[1]=0x49;		//54 mins
	return len;
}

int nas_encode::encode_Tracking_area_identity_list(uint8_t* buf){
	int len=6;
	
	buf[0]=0x54;	//Element ID
	buf[1]=len;
	buf[2]=0x20;	//Type of list & Number of element
	
	buf[3]=0x00;buf[4]=0xf1;buf[5]=0x10;	//MCC+MNC
	buf[6]=0x00;buf[7]=0x01;	//TAC
	
	return len+2;
}

int nas_encode::encode_EPS_bearer_context_status(uint8_t* buf){
	int len=2;
	buf[0]=0x57;	//Element ID
	buf[1]=len;
	buf[2]=0x20;buf[3]=0x00;//EBI
	
	return len+2;
}

int nas_encode::encode_EPS_network_feature_support(uint8_t* buf){
	int len=1;
	buf[0]=0x64;	//Element ID
	buf[1]=len;
	buf[2]=0x01;	
	return len+2;
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
int nas_encode::encode_Tracking_Area_Update_Accept(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : Tracking Area Update Accept\n");
	uint8_t* ss;
	int len=0;
	buf[1]=0x27;	//Integrity and Ciphered
	
	buf[6]=ue->sec.dl_count;
	buf[7]=0x07;	//EMM message
	buf[8]=0x49;	//Tracking area Update Accept
	buf[9]=0x01;	//EPS Update result value: Combined TA/LA update
	
	len+=encode_GPRS_Timer(&buf[10]);
	len+=encode_Tracking_area_identity_list(&buf[10+len]);
	len+=encode_EPS_bearer_context_status(&buf[10+len]);
	len+=encode_EPS_network_feature_support(&buf[10+len]);
	
	buf[0]=9+len;
	
	ss=do_EIA1(ue->sec.k_nasint,&buf[6],4+len,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	return buf[0]+1;
}
int nas_encode::encode_Service_reject(uint8_t* buf,ue_ctx_t* ue){
	printf("Send Message type : Service reject\n");
	
	buf[1] = 0x07;	
	buf[2] = 0x4e;
	buf[3] = 0x12;
	
	buf[0] =0x03;
	
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

int nas_encode::encode_Activate_default_EPS_bearer_context_req(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
	uint8_t* ss;
	buf[1] = 0x27;
	
	buf[6]=ue->sec.dl_count;
	/*
	buf[7] = 0x62; // EPS bear id:6
	buf[8] = 0x02; // Procedure transaction identity:2
	buf[9] = 0xc1; //Activate default EPS bearer conext request
	buf[10] = 0x01; //Length:1
	buf[11] = 0x05; //QCI:5
	buf[12] = 0x04; //Length:4 (fixed)
	&buf[13] = 0x03696d73; //APN:ims
	buf[17] = 0x05; //Length:5 (total len)
	buf[18] = 0x01; //Spare bit(s) & PDN type:IPV4(1)
	&buf[19] = 0xc0a8c80a; //PDN IPv4:192.168.200.10
	
	buf[23] = 0x5e; // ID:APN aggregate maximum bit rate
	buf[24] = 0x02; //Length:2
	buf[25] = 0x97; //APN-AMBR for downlink:2048 kbps
	buf[26] = 0x97; //APN-AMBR for uplink:2048 kbps
	
	buf[27] = 0x58; //ESM cause ID:0X58
	buf[28] = 0x32; //PDN type IPv4 only allowed(50)
	
	buf[29] = 0x27.; //Element ID
	buf[30] = 0x48; //Length:72 (total len)
	buf[31] = 0x80; 
	&buf[32] = 0x8021; //Internet Protocol Control Protocol(0x8021)
	buf[34] = 0x10; //Length:16
	buf[35] = 0x03; //Configuration Nak(3)
	buf[36] = 0x01; //Identifier:1
	&buf[37] = 0x0010; //Length:16 (fixed)
	buf[39] = 0x81; //Primary DNS Server IP Address(129)
	buf[40] = 0x06; //Length:6 (fixed)
	&buf[41] = 0xc0a80764; //DNS Address:192.168.7.100
	buf[45] = 0x83; //Secondary DNS Server IP Address(131)
	buf[46] = 0x06; // Length:6
	&buf[47] = 0x00000000; // Second DNS Address:0.0.0.0
	&buf[51] = 0x0003; //DNS Server IPv6 Address(0x0003)
	buf[53] = 0x10; //Length:16
	&buf[54] = 0x00000000000000000000000000000000 ; //IPv6: ::
		&buf[70] = 0x000d; //DNS Server IPv4 Address(0x000d)
	buf[72] = 0x04; //Length:4
	&buf[73] = 0xc0a80764; //IPv4:192.168.7.100
	
	&buf[77] = 0x000c; //P-CSCF IPv4 Address
	buf[79] = 0x04; //Length:4 (fixed)
	&buf[80] = 0xc0a8076f; //Ipv4:192.168.7.111(IMS Server IP)
	&buf[84] = 0x0001; //P-CSCF Ipv6 Address
	buf[86] = 0x10; //Length:10 (fixed)
	&buf[87] = 0x00000000000000000000000000000000;//Ipv6: ::  (buf[102])
	*/
	
	
	char c[]="6202c101050403696d730501c0a8c80a5e0297975832274880802110030100108106c0a8076483060000000000031000000000000000000000000000000000000d04c0a80764000c04c0a8076f00011000000000000000000000000000000000";
	c2u(&buf[7],c,96);
	
	ss=do_EIA1(ue->sec.k_nasint,&buf[6],97,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	
	buf[0] = 102;
	return buf[0]+1;
} 

int nas_encode::encode_Activate_default_EPS_bearer_context_req_qci1(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
	uint8_t* ss;
	buf[1] = 0x27;
	
	buf[6]=ue->sec.dl_count;
	/*
	buf[7] = 0x72; // EPS bear id:7
	buf[8] = 0x00; // Procedure transaction identity:0
	buf[9] = 0xc5; //Activate dedicated EPS bearer conext request
	buf[10] = 0x06; //EPS bearer identity value 6
	buf[11] = 0x05; //Length:5
	buf[12] = 0x01; //qci:1
	buf[13] = 0x87; buf[14] = 0x87; //Maximum bit rate 
	buf[15] = 0x87; buf[16] = 0x87; //Guaranteed bit rate
	
	buf[16] = 0x51; Length:81
	buf[17] = 0x24; //TFT,nUMBER OF Packet filters:4
	buf[18] = 0x20; //spare bits:0,Uplink only(2)
	buf[19] = 0x30; // Packet elvaluation precedence:48
	buf[20] = 0x11; //Packetfilter length:17
	buf[21] = 0x10; //IPv4 remote address type(16)
	&buf[22] = 0xc0a7076e; //?? ims server
	&buf[26] = 0xffffffff; //IPv4 address mask:255.255.255.255
	buf[30] = 0x30;  //Protocol identifier/Next header type(48)
	buf[31] = 0x11; //Protocol/header:UDP
	buf[32] = 0X40; //Single locol port type
	&buf[33] = 0xc35a; //??RTP Port: 50010;
	buf[35] = 0x50; //Single remote port type 
	&buf[36] = 0x9156; // Port:37206
	
	buf[38] = 0x11; // Spare bits ,Downlink only ,Packetfilter identifier :2
	buf[39] =0x31; //Packet evaluation precedence:49
	buf[40] = 0x11; //Packet filter length
	buf[41] = 0x10; //IPv4 remote address type(16)
	&buf[42] = 0xc0a7076e; //?? ims server
	&buf[46] = 0xffffffff; //IPv4 address mask:255.255.255.255
	buf[50] = 0x30;  //Protocol identifier/Next header type(48)
	buf[51] = 0x11; //Protocol/header:UDP
	buf[52] = 0X40; //Single locol port type(64)
	&buf[53] = 0xc35a; //??RTP Port: 50010;
	buf[55] = 0x50; //Single remote port type 
	&buf[56] = 0x9156; // Port:37206
	
	buf[58] = 0x22; //Sparebit,Uplink only,Packet filter identifier:3
	buf[59] =0x36; //Packet evaluation precedence:54
	buf[60] = 0x11; //Packet filter length
	buf[61] = 0x10; //IPv4 remote address type(16)
	&buf[62] = 0xc0a7076e; //?? ims server
	&buf[66] = 0xffffffff; //IPv4 address mask:255.255.255.255
	buf[70] = 0x30;  //Protocol identifier/Next header type(48)
	buf[71] = 0x11; //Protocol/header:UDP
	buf[72] = 0X40; //Single locol port type(64)
	&buf[73] = 0xc35b; //??RTP Port: 50011;
	buf[75] = 0x50; //Single remote port type 
	&buf[76] = 0x9157; // Port:37207
	
	buf[78] = 0x13; //Sparebit,Uplink only,Packet filter identifier:4
	buf[79] =0x37; //Packet evaluation precedence:55
	buf[80] = 0x11; //Packet filter length
	buf[81] = 0x10; //IPv4 remote address type(16)
	&buf[82] = 0xc0a7076e; //?? ims server
	&buf[86] = 0xffffffff; //IPv4 address mask:255.255.255.255
	buf[90] = 0x30;  //Protocol identifier/Next header type(48)
	buf[91] = 0x11; //Protocol/header:UDP
	buf[92] = 0X40; //Single locol port type(64)
	&buf[93] = 0xc35b; //??RTP Port: 50011;
	buf[95] = 0x50; //Single remote port type 
	&buf[96] = 0x9157; // Port:37207

	*/
	
	char c[]="7200c506050187878787512420301110c0a7076effffffff301140c35a50915611311110c0a7076effffffff301140c35a50915622361110c0a7076effffffff301140c35850915713371110c0a7076effffffff301140c35b509157";
	c2u(&buf[7],c,92);
	ss=do_EIA1(ue->sec.k_nasint,&buf[6],93,ue->sec.int_al,&ue->sec.dl_count);
	memcpy(&buf[2],ss,4);
	
	buf[0] = 98;
	return buf[0]+1;
	
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
