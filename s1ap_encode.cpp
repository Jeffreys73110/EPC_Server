#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "s1ap_common.h"
#include "s1ap_encode.h"
#include "nas_encode.h"
#include "sec/f1.h"
s1ap_encode* s1ap_encode::m_instance=NULL;
pthread_mutex_t s1ap_encode_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

s1ap_encode::s1ap_encode(){

}
void s1ap_encode::init(){
	m_nas_encode=nas_encode::get_instance();
}
s1ap_encode* s1ap_encode::get_instance(){
	pthread_mutex_lock(&s1ap_encode_instance_mutex);
	if(NULL==m_instance){
		m_instance=new s1ap_encode();
	}
	pthread_mutex_unlock(&s1ap_encode_instance_mutex);
	return m_instance;
}
int char_hex_to_int(char a){
	return ((a>'9')?(a-87):(a-48));
}
int s1ap_encode::encode_MMEname(uint8_t* buf,s1ap_args_t* args){
	int i,len=strlen(args->MMEname);
	buf[0]=0;
	buf[1]=0x3d;	//MMEname
	buf[2]=0x40;	//ignore
	buf[3]=2+len;
	buf[4]=((len-1)>>1);
	buf[5]=((len-1)<<7);
	for(i=0;i<len;i++) buf[6+i]=args->MMEname[i];
	return 6+len;
}
int s1ap_encode::encode_pLMN(uint8_t* buf,s1ap_args_t* args){
	int i;
	buf[0]=((args->len_ServedGUMMEIs-1)<<5)+(0<<3)+((args->len_ServedpLMNs-1)>>2);
	buf[1]=(args->len_ServedpLMNs-1)<<6;
	for(i=0;i<args->len_ServedpLMNs;i++){
		buf[2+i*3]=(char_hex_to_int(args->Served_pLMN[i][0])<<4)+char_hex_to_int(args->Served_pLMN[i][1]);
		buf[3+i*3]=(char_hex_to_int(args->Served_pLMN[i][2])<<4)+char_hex_to_int(args->Served_pLMN[i][3]);
		buf[4+i*3]=(char_hex_to_int(args->Served_pLMN[i][4])<<4)+char_hex_to_int(args->Served_pLMN[i][5]);
	}
	return args->len_ServedpLMNs*3+2;
}
int s1ap_encode::encode_ServedGroupID(uint8_t* buf,s1ap_args_t* args){
	int i;
	buf[0]=(args->len_ServedGroupID-1)>>8;
	buf[1]=(args->len_ServedGroupID-1)&0xff;
	for(i=0;i<args->len_ServedGroupID;i++){
		buf[2+2*i]=args->Served_MME_Group_ID[i]>>8;
		buf[3+2*i]=args->Served_MME_Group_ID[i]&0xff;
	}
	return 2+2*args->len_ServedGroupID;
}
int s1ap_encode::encode_ServedMMECs(uint8_t* buf,s1ap_args_t* args){
	int i;
	buf[0]=args->len_ServedMMECs-1;
	for(i=0;i<args->len_ServedMMECs;i++)
		buf[1+i]=args->Served_MME_Code[i];
	return 1+i;
}
int s1ap_encode::encode_ServedGUMMEIs(uint8_t* buf,s1ap_args_t* args){
	buf[0]=0; buf[1]=0x69;
	buf[2]=0;
//TODO: test length>1
	int len=encode_pLMN(&buf[4],args);
	len+=encode_ServedGroupID(&buf[4+len],args);
	len+=encode_ServedMMECs(&buf[4+len],args);
	buf[3]=len;
	return len+4;
}
int s1ap_encode::encode_RelativeMMECapacity(uint8_t* buf,s1ap_args_t* args){
	buf[0]=0; buf[1]=0x57;
	buf[2]=0x40;
	buf[3]=1;
	buf[4]=args->RelativeMMECapacity;
	return 5;
}
int s1ap_encode::encode_initiate_message(uint8_t* buf,s1ap_args_t* args){
	int len=0;
	buf[1]=0; //initiate_message: no extension
	buf[2]=0; buf[3]=3; //length=3
	len+=encode_MMEname(&buf[4],args);
	len+=encode_ServedGUMMEIs(&buf[4+len],args);
	len+=encode_RelativeMMECapacity(&buf[4+len],args);

	buf[0]=len+3;
	return len+3;
}
int s1ap_encode::encode_S1Response_message(uint8_t* buf,s1ap_args_t* args){
	buf[0]=0x20; //successfulOutcome
	buf[1]=0x11;    //id-S1Setup
	buf[2]=0x00;	//reject
	int len=encode_initiate_message(&buf[3],args)+4;
	return len;
}
int s1ap_encode::encode_MME_UE_S1AP_ID(uint8_t* buf,uint32_t mme_ue_s1ap_id){
	int i=0,j=0;
	uint32_t temp=mme_ue_s1ap_id;
	printf("mme ue id:%08x\n",temp);
	while(temp>0){j++; temp>>=1;}
	buf[0]=0x00; buf[1]=0x00; //MME-UE-S1AP-ID
	buf[2]=0x00;	//reject
	buf[3]=(j+7)/8+1;
	buf[4]=(buf[3]-2)<<6;
	for(i=0;i<buf[3]-1;i++) buf[5+i]=((mme_ue_s1ap_id>>((buf[3]-2-i)*8))&0xff);
	return buf[3]+4;
}
int s1ap_encode::encode_ENB_UE_S1AP_ID(uint8_t* buf,uint32_t enb_ue_s1ap_id){
	int i=0,j=0;
	uint32_t temp=enb_ue_s1ap_id;
	while(temp>0){j++; temp>>=1;}
	buf[0]=0x00; buf[1]=0x08; //ENB-UE-S1AP-ID
	buf[2]=0x00;	//reject
	buf[3]=(j+7)/8+1;
	buf[4]=(buf[3]-2)<<6;
	for(i=0;i<buf[3]-1;i++) buf[5+i]=((enb_ue_s1ap_id>>((buf[3]-2-i)*8))&0xff);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_Identity_Request_IMSI(uint8_t* buf){
	buf[0]=0x00; buf[1]=0x1a; //NAS-PDU
	buf[2]=0x00;	//reject
	buf[3]=m_nas_encode->encode_Identity_Request_message_IMSI(&buf[4]);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_Authentication_Request(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a; //NAS-PDU
	buf[2]=0x00;	//reject
	buf[3]=m_nas_encode->encode_Authentication_Request(&buf[4],ue);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_Security_Mode_Command(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a; //NAS-PDU
	buf[2]=0x00;	//reject
	buf[3]=m_nas_encode->encode_Security_Mode_Command(&buf[4],ue);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_EMM_Information_Request(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a;
	buf[2]=0x00;
	buf[3]=m_nas_encode->encode_EMM_Information_Request(&buf[4],ue);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_ESM_Information_Request(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a;
	buf[2]=0x00;
	buf[3]=m_nas_encode->encode_ESM_Information_Request(&buf[4],ue);
	return buf[3]+4;
}
int s1ap_encode::encode_NAS_PDU_Tracking_Area_Update_Accept(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a;	//id-NAS-PDU
	buf[2]=0x00;	//reject
	buf[3]=m_nas_encode->encode_Tracking_Area_Update_Accept(&buf[4],ue);
	return buf[3]+4;
}

int s1ap_encode::encode_NAS_PDU_Service_reject(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x1a;	//id-NAS-PDU
	buf[2]=0x00;	//reject
	buf[3]=m_nas_encode->encode_Service_reject(&buf[4],ue);
	return buf[3]+4;
}

/*
int s1ap_encode::encode_(uint8_t* buf,ue_ctx_t* ue){
	
}
*/
int s1ap_encode::encode_Identity_Request_message(uint8_t* buf,uint32_t* mme_ue_s1ap_id,uint32_t* enb_ue_s1ap_id){
	int len=0;
	buf[0]=0x00; 	//InitiatingMessage
	buf[1]=0x0b;	//id-downlinkNASTransport
	buf[2]=0x40;	//ignore
	buf[4]=0x00;	//no extension for protocolIEs
	buf[5]=0x00; buf[6]=0x03;	//3 protocolIEs
	
	len+=encode_MME_UE_S1AP_ID(&buf[7],*mme_ue_s1ap_id); 
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],*enb_ue_s1ap_id);
	len+=encode_NAS_PDU_Identity_Request_IMSI(&buf[7+len]);

	buf[3]=len+3;
	return buf[3]+4;
}
int s1ap_encode::encode_Authentication_Request_message(uint8_t* buf,ue_ctx_t* ue){
	int len=0,i;
	buf[0]=0x00;	//InitiatingMessage
	buf[1]=0x0b;	//id-downlinkNASTransport
	buf[2]=0x40;	//ignore
	buf[4]=0x00;	//no extension for protocolIEs
	buf[5]=0x00; buf[6]=0x03;	//3 protocolIEs

	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_Authentication_Request(&buf[7+len],ue);

	buf[3]=len+3;
	return buf[3]+4;
}
int s1ap_encode::encode_Security_Mode_Command_message(uint8_t* buf,ue_ctx_t* ue){
	int len=0,i;
	buf[0]=0x00;	//InitiatingMessage
	buf[1]=0x0b;	//id-downlinkNASTransport
	buf[2]=0x40;	//ignore
	buf[4]=0x00;	//no extension for protocolIEs
	buf[5]=0x00; buf[6]=0x03;	//3 protocolIEs

	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_Security_Mode_Command(&buf[7+len],ue);

	buf[3]=len+3;
	return buf[3]+4;
}
int s1ap_encode::encode_EMM_Information_Request_message(uint8_t* buf,ue_ctx_t* ue){
	int len=0,i;
	buf[0]=0x00;
	buf[1]=0x0b;
	buf[2]=0x40;
	buf[4]=0x00;
	buf[5]=0x00; buf[6]=0x03;
	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_EMM_Information_Request(&buf[7+len],ue);

	buf[3]=len+3;
	return buf[3]+4;
}
int s1ap_encode::encode_ESM_Information_Request_message(uint8_t* buf,ue_ctx_t* ue){
	int len=0,i;
	buf[0]=0x00;
	buf[1]=0x0b;
	buf[2]=0x40;
	buf[4]=0x00;
	buf[5]=0x00; buf[6]=0x03;
	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_ESM_Information_Request(&buf[7+len],ue);

	buf[3]=len+3;
	return buf[3]+4;
}
int s1ap_encode::encode_Tracking_Area_Update_Accept(uint8_t* buf, ue_ctx_t* ue){
	int len=0,i;
	buf[0]=0x00; 
	buf[1]=0x0b;	//id-downlinkNASTransport
	buf[2]=0x40;	//ignore
	
	buf[4]=0x00;
	buf[5]=0x00; buf[6]=0x03;	//3 items
	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_Tracking_Area_Update_Accept(&buf[7+len],ue);
	
	buf[3]=len+3;
	return buf[3]+4;
}
int encode_uEaggregateMaximumBitrate(uint8_t* buf){
	buf[0]=0x00; buf[1]=0x42;//id-uEaggregateMaximumBitrate
	buf[2]=0x00;	//reject
	buf[3]=0x08;	//len
	buf[4]=0x10;buf[5]=0x20;buf[6]=0x00;buf[7]=0x00;//DL<00>:ext preamble <010>:len=2+1 <000>:padding
	buf[8]=0x40;buf[9]=0x20;buf[10]=0x00;buf[11]=0x00;//UL<010>:len=2+1 <00000>:padding
	return buf[3]+4;
}
int encode_ims_uEaggregateMaximumBitrate(uint8_t* buf){
	buf[0]=0x00; buf[1]=0x42;//id-uEaggregateMaximumBitrate
	buf[2]=0x00;	//reject
	buf[3]=0x08;	//len
	buf[4]=0x10;buf[5]=0x30;buf[6]=0x00;buf[7]=0x00;//DL<00>:ext preamble <010>:len=2+1 <000>:padding
	buf[8]=0x40;buf[9]=0x30;buf[10]=0x00;buf[11]=0x00;//UL<010>:len=2+1 <00000>:padding
	return buf[3]+4;
}
int s1ap_encode::encode_UESecurityCapabilities(uint8_t* buf,ue_ctx_t* ue){
	buf[0]=0x00; buf[1]=0x6b;//id
	buf[2]=0x00; buf[3]=0x05;
	
	//buf[4]=((ue->prop.msg_type.ar.ue_cap.eea[1]<<4)+(ue->prop.msg_type.ar.ue_cap.eea[2]<<3));	//<0>ext <0>preamble <0>ext range <11000.000> EEA1&EEA2
	//buf[4]=(0x10*ue->prop.msg_type.ar.ue_cap.eea[1])+(0x08*ue->prop.msg_type.ar.ue_cap.eea[2]);
	buf[4]=0x1c;
	buf[5]=0x00;
	
	//buf[6]=((ue->prop.msg_type.ar.ue_cap.eia[1]<<3)+(ue->prop.msg_type.ar.ue_cap.eia[2]<<2));	//<0> <1100.0000> EIA1&EIA2
	//buf[6]=(0x08*ue->prop.msg_type.ar.ue_cap.eia[1])+(0x04*ue->prop.msg_type.ar.ue_cap.eia[2]);
	buf[6]=0x0e;
	buf[7]=0x00;
	buf[8]=0x00;
	return buf[3]+4;
}
int s1ap_encode::encode_ERABToSetupListCtxtSUReq(uint8_t* buf,ue_ctx_t* ue,int ebi,int msg_type){
	int len=0;
	buf[0]=0x00; buf[1]=0x18;
	buf[2]=0x00;	//reject
	
	buf[4]=0x00; 	//item len
	buf[5]=0x00; buf[6]=0x34; //id-E-RABToBeSetupItemCtxtSUReq
	buf[7]=0x00;	//reject
	
	//for attach accept
	if(msg_type==0x42){	
		buf[9]=0x45;	//<0>ext flag <1>nas-pdu <0>no IE-Ext <0101> e-rab id
		buf[10]=0x00;	//<0>gbrQosInformation <0>no IE-Ext
		buf[11]=0x09;	//qCI
		buf[12]=0x24;	//<0>AllocationAndRetentionPriority ext flag <0>no IE-Ext <1001>qCI:9 <0> pre-emptionCapability <0> pre-emptionVulnerability
		buf[13]=0x0f; buf[14]=0x80; //TransportLayerAddress <0>ext range <000111111>:len=31+1
		memcpy(&buf[15],&ue->erab[ebi].s1u_ipv4,4);
		memcpy(&buf[19],&ue->erab[ebi].s1u_sgw_fteid,4);
		len+=m_nas_encode->encode_Attach_Accept(&buf[23],ue);
		printf("s1ap_encode_erabtosetuplistctxtsureq: len:%02x buf[3]:%02x\n",len,buf[3]);
		buf[3] = len + 19;
		buf[8] = len + 14;
	}
	//for UECapabilityInformation
	else if(msg_type==0x74){
		buf[9]=0x05;	//<0>ext flag <0>nas-pdu <0>no IE-Ext <0101> e-rab id
		buf[10]=0x00;	//<0>gbrQosInformation <0>no IE-Ext
		buf[11]=0x09;	//qCI
		buf[12]=0x24;	//AllocationAndRetentionPriority <0>ext flag <0>no IE-Ext <1001>PriorityLevel(9) <0>shall-not-trigger-pre-emption <0>not-pre-emptable
		buf[13]=0x0f; buf[14]=0x80; //TransportLayerAddress <0>ext range <000111111>:len=31+1
		memcpy(&buf[15],&ue->erab[ebi].s1u_ipv4,4);
		memcpy(&buf[19],&ue->erab[ebi].s1u_sgw_fteid,4);
		printf("s1ap_encode_erabtosetuplistctxtsureq: len:%02x buf[3]:%02x\n",len,buf[3]);
		buf[3] = len + 19;
		buf[8] = len + 14;	
	}
	return buf[3]+4;
}
int s1ap_encode::encode_ERABToBeSetupListBearerSUReq(uint8_t* buf,ue_ctx_t* ue){
	int len =0;
	buf[0] = 0x00; buf[1] = 0x10; //id-E-RABToBeSetupListBearerSUReq
	buf[2] = 0x00;  //reject
	
	buf[4] = 0x00; // one item & sequence len
	buf[5] = 0x00; buf[6] = 0x11; //id-E-RABToBeSetupListBearerSUReq
	buf[7] = 0x00 ; //reject
	
	// enter encoder nas 
	buf[9] = 0x0c; //<0>ext flag <0>no IE-Ext <1100> e-rab id
	buf[10] = 0x00;	//<0>gbrQosInformation <0>no IE-Ext 
	buf[11] = 0x05; //QCI:5
	buf[12]=0x04;	//AllocationAndRetentionPriority <0>ext flag <0>no IE-Ext <0001>PriorityLevel(1) <0>shall-not-trigger-pre-emption <0>not-pre-emptable
	buf[13]=0x0f; buf[14]=0x80; //TransportLayerAddress <0>ext range <000111111>:len=31+1
	memcpy(&buf[15],&ue->erab[6].s1u_ipv4,4);
	memcpy(&buf[19],&ue->erab[6].s1u_sgw_fteid,4);
	//buf[19] = 0x00; buf[20] = 0x00; buf[21] = 0x00; buf[22] =0x21;
	len+=m_nas_encode->encode_Activate_default_EPS_bearer_context_req(&buf[23],ue);
	
	buf[8] = len + 14;
	buf[3] = len + 19;
	return buf[3]+4;
}

int s1ap_encode::encode_ERABToBeSetupListBearerSUReq_qci1(uint8_t* buf,ue_ctx_t* ue){
	int len =0;
	buf[0] = 0x00; buf[1] = 0x10; //id-E-RABToBeSetupListBearerSUReq
	buf[2] = 0x00;  //reject
	buf[3] = 0x80; //Length over flow
	
	buf[5] = 0x00; // one item & sequence len
	buf[6] = 0x00; buf[7] = 0x11; //id-E-RABToBeSetupListBearerSUReq
	buf[8] = 0x00; //reject
	buf[9] = 0x80; //Length Over flow
	// enter encoder nas 
	buf[11] = 0x0e; //<0>ext flag <0>no IE-Ext <0101> e-rab id
	
	buf[12] = 0x80;	//<0>gbrQosInformation <1> IE-Ext 
	buf[13] = 0x01; //QCI:1
	buf[14]=0x17;	//AllocationAndRetentionPriority
	buf[15]=0x10; buf[16]=0x0f; buf[17]=0xa0; buf[18]=0x00; buf[19]=0x40; buf[20]=0x0f; buf[21]=0xa0; buf[22]=0x00; buf[23]=0x40; //gbrQosInformation
	buf[24]=0x0f; buf[25]=0xa0; buf[26]=0x00; buf[27]=0x40; buf[28]=0x0f; buf[29]=0xa0; buf[30]=0x00;
	
	buf[31]=0x0f; buf[32]=0x80;
	memcpy(&buf[33],&ue->erab[7].s1u_ipv4,4);
	memcpy(&buf[37],&ue->erab[7].s1u_sgw_fteid,4);
	len+=m_nas_encode->encode_Activate_default_EPS_bearer_context_req_qci1(&buf[41],ue);
	
	buf[10] = len + 30;
	buf[4] = len + 36;
	return buf[4]+5;
}


int s1ap_encode::encode_SecurityKey(uint8_t* buf,ue_ctx_t* ue){
	
	static bool first_time=1;
	//if(first_time){						//Only execute in first time
	if(1){
		uint8_t k_enb[32];
		get_k_enb(ue,k_enb);
		buf[0]=0x00; buf[1]=0x49;
		buf[2]=0x00;
		buf[3]=0x20;//len
		memcpy(&buf[4],k_enb,32);
		
		memcpy(ue->sec.k_enb,k_enb,32);
		first_time=0;
	}
	/*
	else{
		uint8_t NH[32];
		//get_k_enb_star(ue,NH);
		buf[0]=0x00; buf[1]=0x49;
		buf[2]=0x00;
		buf[3]=0x20;//len
		get_k_enb(ue,NH);
		
		get_Next_Hop(ue, NH);
		memcpy(ue->sec.k_enb,NH,32);
		get_Next_Hop(ue, NH);
		memcpy(ue->sec.k_enb,NH,32);
		get_k_enb_star(ue, NH);
		
		memcpy(ue->sec.k_enb,NH,32);
		
		memcpy(&buf[4],NH,32);
	}
	*/
	return buf[3]+4;
}
int s1ap_encode::encode_SRVCCOperationPossible(uint8_t* buf){
	buf[0] = 0x00; buf[1] = 0x7c;	//id-SRVCCOperationPossible
	buf[2] = 0x40;	//ignore
	buf[3] = 0x01;	//len
	buf[4] = 0x00;	//possible
	return 5;
}
int s1ap_encode::encode_UERadioCapability(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
	buf[0]=0x00; buf[1]=0x4a;	//id-UERadioCapability
	buf[2]=0x40;				//ignore
	int c_len=72; char c[]="023201043c59ad48001060e6d2a64ea0448ff8fff23fe3ffc8ff8fff23fe3ffc8ff8fff23fe3ffc8ff8fff23fe3ffc8ff8fffff9ffd7d103004870ca74a93bbe069c08000006c000";

	c2u(&buf[5],c,c_len);
	buf[3]=c_len+1; buf[4]=c_len;
	
	return c_len+5;
}
int s1ap_encode::encode_UE_S1AP_IDs(uint8_t* buf,ue_ctx_t* ue){
	int len=0,i=0,j=0;
	buf[0]=0x00; buf[1]=0x63;//id-UE-S1AP-IDs
	buf[2]=0x00;	//reject
	
	uint32_t temp=ue->MME_UE_ID;
	while(temp>0){j++; temp>>=1;}
	temp=ue->MME_UE_ID;
	buf[4]=((j+7)/8-1)<<2;
	for(i=0;i<(j+7)/8;i++) buf[5+i]=((temp>>(((j+7)/8-1-i)*8))&0xff);
	
	temp=ue->eNB_UE_ID;
	j=0;
	while(temp>0){j++; temp>>=1;}
	temp=ue->eNB_UE_ID;
	buf[9]=((j+7)/8-1)<<6;;
	for(i=0;i<(j+7)/8;i++) buf[10+i]=((temp>>(((j+7)/8-1-i)*8))&0xff);
	buf[3]=0x08;	//len
	
	return 12;
}
int s1ap_encode::encode_Cause(uint8_t* buf){
	buf[0]=0x00; buf[1]=0x02;	//id-Cause
	buf[2]=0x40;	//ignore
	buf[3]=0x02;	//len
	buf[4]=0x00;	//Choice : radioNetwork
	buf[5]=0x60;	//release-due-to-eutran-generated-reason
	return 6;
}
int s1ap_encode::encode_InitialContextSetupRequest_message(uint8_t* buf,ue_ctx_t* ue,int ebi){
	int len=0,i;
	buf[0]=0x00;
	buf[1]=0x09;	//InitialContextSetup
	buf[2]=0x00;	//reject
	
	buf[5]=0x00;	// no ext.
	//buf[6]=0x00; buf[7]=0x06; // protocolIE-Field Num
	buf[6]=0x00; buf[7]=0x07; // protocolIE-Field Num
	len+=encode_MME_UE_S1AP_ID(&buf[8],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[8+len],ue->eNB_UE_ID);
	len+=encode_uEaggregateMaximumBitrate(&buf[8+len]);	//TODO: this should be dependent with ue?
	len+=encode_ERABToSetupListCtxtSUReq(&buf[8+len],ue,5,0x42);//attach accept(0x42)
	len+=encode_UESecurityCapabilities(&buf[8+len],ue);
	len+=encode_SecurityKey(&buf[8+len],ue);
	len+=encode_SRVCCOperationPossible(&buf[8+len]);
	buf[3] = 0x80; buf[4] = len+3;
	
	return buf[4]+5;
}
int s1ap_encode::encode_InitialContextSetupRequest_UECapabilityInformation_message(uint8_t* buf, ue_ctx_t* ue){
	int len=0;
	buf[0]=0x00;
	buf[1]=0x09;	//InitialContextSetup
	buf[2]=0x00;	//reject
	
	buf[5]=0x00; //no ext.
	buf[6]=0x00; buf[7]=0x08;	// protocolIE-Field Num
	
	len+=encode_MME_UE_S1AP_ID(&buf[8+len],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[8+len],ue->eNB_UE_ID);
	len+=encode_uEaggregateMaximumBitrate(&buf[8+len]);	//TODO: this should be dependent with ue?
	len+=encode_ERABToSetupListCtxtSUReq(&buf[8+len],ue,5,0x74);//UECapabilityInformation(0x74)
	len+=encode_UESecurityCapabilities(&buf[8+len],ue);
	len+=encode_SecurityKey(&buf[8+len],ue);
	len+=encode_UERadioCapability(&buf[8+len],ue);
	len+=encode_SRVCCOperationPossible(&buf[8+len]);
	buf[3] = 0x80; buf[4] = len+3;	//len
	
	return buf[4]+5;
}
int s1ap_encode::encode_UEContextReleaseCommand_message(uint8_t* buf, ue_ctx_t* ue){
	int len=0;
	buf[0]=0x00; buf[1]=0x17;	//id-UEContextRelease
	buf[2]=0x00;	//reject
	buf[4]=0x00;	//no ext.
	buf[5]=0x00; buf[6]=0x02;	//protocolIE-Field Num
	len+=encode_UE_S1AP_IDs(buf+7,ue);
	len+=encode_Cause(buf+len+7);
	buf[3]=len+3;
	return buf[3]+4;
}

int s1ap_encode::encode_PDN_connectivity_response(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
	buf[0] = 0x00;
	buf[1] = 0x05;
	buf[2] = 0x00;
	buf[3] = 0x80; //Length overflow
	buf[5] = 0x00;
	buf[6] = 0x00;  buf[7] = 0x04; //4個item
	/*
	buf[7] = 0x00; buf[8] = 0x00; //id-MME-UE-S1AP-ID
	buf[9] = 0x00; //reject
	buf[10] = 0x05; //剩餘長度
	buf[11] = 0xc0; buf[12] = 0xce; buf[13] = 0x59; buf[14] = 0x49; buf[15] = 0xd1; //ID:3461958097
	*/
	len+=encode_MME_UE_S1AP_ID(&buf[8],ue->MME_UE_ID);
	/*
	buf[16] = 0x00; buf[17] = 0x08; //id-eNB-UE-S1AP-ID;
	buf[18] = 0x00; //reject
	buf[19] = 0x03; // 剩餘長度
	buf[20] = 0x40; buf[21] =0x01; buf[22] = 0x01; //ENB-UE-S1AP-ID:257
	*/
	len+=encode_ENB_UE_S1AP_ID(&buf[8+len],ue->eNB_UE_ID);
	len+=encode_ims_uEaggregateMaximumBitrate(&buf[8+len]);
	len+=encode_ERABToBeSetupListBearerSUReq(&buf[8+len],ue);
	buf[4]=len+3;	
	return buf[4]+5;
	
}


int s1ap_encode::encode_ERABSetRequest_message(uint8_t* buf,ue_ctx_t* ue,int ebi){
	int len=0;
	buf[0] = 0x00;
	buf[1] = 0x05;
	buf[2] = 0x00; //reject
	buf[3] = 0x80; //Length overflow
	buf[5] = 0x00;
	buf[6] = 0x00;  buf[7] = 0x04; //4個item
	
	len+=encode_MME_UE_S1AP_ID(&buf[8],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[8+len],ue->eNB_UE_ID);
	len+=encode_ims_uEaggregateMaximumBitrate(&buf[8+len]);
	len+=encode_ERABToBeSetupListBearerSUReq_qci1(&buf[8+len],ue);
	
	buf[4]=len+3;	
	return buf[4]+5;
}


int s1ap_encode::encode_service_reject(uint8_t* buf,ue_ctx_t* ue){
	int len=0;
	buf[0] = 0x00;
	buf[1] = 0x0b;
	buf[2] = 0x40; //ignore
	buf[4] = 0x00;
	buf[5] = 0x00;  buf[6] = 0x03; //3個item
	
	len+=encode_MME_UE_S1AP_ID(&buf[7],ue->MME_UE_ID);
	len+=encode_ENB_UE_S1AP_ID(&buf[7+len],ue->eNB_UE_ID);
	len+=encode_NAS_PDU_Service_reject(&buf[7+len],ue);
	buf[3]=len+3;
	
	return buf[3]+4;
}

/*
int main(){
	char c[]="20110053000003003d40381a806d6d656330312e6d6d656769383030302e6d6d652e6570632e6d6e633030312e6d63633030312e336770706e6574776f726b2e6f72670069000b000000f1100000800000010057400101";
	initiate_args();
	uint8_t buf[100];
	encode_S1response(buf);
	int i;
	for(i=0;2*i<strlen(c);i++){
		printf("%d: %c%c %02x\n",i,c[2*i],c[2*i+1],buf[i]);
	}
	print_args_info();
}*/
