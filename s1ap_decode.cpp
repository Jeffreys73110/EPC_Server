#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<pthread.h>
#include"s1ap_common.h"
#include"s1ap_decode.h"
s1ap_decode* s1ap_decode::m_instance=NULL;
pthread_mutex_t s1ap_decode_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

s1ap_decode::s1ap_decode(){

}
void s1ap_decode::init(){
	m_nas_decode=nas_decode::get_instance();
}
s1ap_decode* s1ap_decode::get_instance(){
	pthread_mutex_lock(&s1ap_decode_instance_mutex);
	if(m_instance==NULL){
		m_instance=new s1ap_decode();
	}
	pthread_mutex_unlock(&s1ap_decode_instance_mutex);
	return m_instance;
}
/******************************************************************************
 *									      *
 *				decode ProtocolIE 			      *
 *									      *
 ******************************************************************************/
void s1ap_decode::decode_pLMN(uint8_t* buf,char* pLMN,enb_ctx_t* enb,bool is_decode_pLMN){
	int i=0,s[]={1,0,3,5,4,2};
	for(i=0;i<3;i++){	
		pLMN[i*2]=(buf[i])>>4;
		pLMN[i*2+1]=(buf[i]&0x0f);
		if(pLMN[i*2]>9) pLMN[i*2]=pLMN[i*2]+87;
		else pLMN[i*2]=pLMN[i*2]+48;
		if(pLMN[i*2+1]>9) pLMN[i*2+1]=pLMN[i*2+1]+87;
		else pLMN[i*2+1]=pLMN[i*2+1]+48;
	}
	pLMN[6]=0;
	if(!is_decode_pLMN) return;
	for(i=0;i<3;i++)
		if(pLMN[s[i]]!='f') enb->MCC[i]=pLMN[s[i]];
		else enb->MCC[i]=0;
	enb->MCC[3]=0;
	for(i=0;i<3;i++)
		if(pLMN[s[i+3]]!='f') enb->MNC[i]=pLMN[s[i+3]];
		else enb->MNC[i]=0;
	enb->MNC[i]=0;
}
void s1ap_decode::decode_homeENB_ID(uint8_t* buf,enb_ctx_t* enb){
	enb->homeENB_ID=(uint32_t(buf[0])<<20)+(uint32_t(buf[1])<<12)+(uint32_t(buf[2])<<4)+(uint32_t(buf[3])>>4);

}
void s1ap_decode::decode_macroENB_ID(uint8_t* buf,enb_ctx_t* enb){
	enb->macroENB_ID=(uint32_t(buf[0])<<12)+(uint32_t(buf[1])<<4)+(uint32_t(buf[2])>>4);
}
void s1ap_decode::decode_ProtocolIE_Global_ENB_ID(uint8_t* buf,enb_ctx_t* enb){
	if(buf[0]&(1<<7)){
		printf("decode_ProtocolIE_Global_ENB_ID: expand data\n");
	}
	else{
		if(buf[0]&(1<<6)){
			printf("decode_ProtocolIE_Global_ENB_ID: iE-Extensions\n");
		}
		decode_pLMN(buf+1,enb->pLMN,enb,1);
		if(buf[4]&(1<<7)){
			printf("decode_ProtocolIE_Global_ENB_ID: ENB-ID expand data\n");
		}
		if(buf[4]&(1<<6)){
			enb->type=ENODEB_TYPE_HOMEENB;
			decode_homeENB_ID(buf+5,enb);
		}
		else{
			enb->type=ENODEB_TYPE_MACROENB;
			decode_macroENB_ID(buf+5,enb);
		}
	}
}
void s1ap_decode::decode_ProtocolIE_eNBname(uint8_t* buf,enb_ctx_t* enb){
	int len,i;
	if(buf[0]&(1<<7)){
		printf("decode_ProtocolIE_eNBname: expand length\n");
	}
	else{
		len=(buf[0]<<1)+(buf[1]>>7)+1;
		for(i=0;i<len;i++){
			enb->name[i]=buf[2+i];
		}
		enb->name[len]=0;
	}
}
void s1ap_decode::decode_ProtocolIE_SupportedTAs(uint8_t* buf,enb_ctx_t* enb){
	int num_item,i,index=0;
	num_item=buf[0]+1;
	enb->len_TAC=num_item;
	if(num_item>10) {printf("#error:decode_SupportedTAs: Segmentation fault: Item>10\n"); exit(1);}
	for(i=0;i<num_item;i++){
		if(buf[1+index]&(1<<7)) printf("decode_ProtocolIE_expand\n");
		if(buf[1+index]&(1<<6)) printf("decode_ProtocolIE_extension\n");
		enb->TAC[i][0]=(buf[1+index]&0x3f)>>2;
		enb->TAC[i][1]=((buf[1+index]&0x03)<<2)+(buf[2+index]>>6);
		enb->TAC[i][2]=(buf[2+index]&0x3f)>>2;
		enb->TAC[i][3]=((buf[2+index]&0x03)<<2)+(buf[3+index]>>6);
		
		int len,j;
		for(j=0;j<4;j++)
			enb->TAC[i][j]+=((enb->TAC[i][j]>9)?87:48);
		len=((buf[3+index]&0x38)>>5)+1;
		enb->len_broadcastpLMNs=len;
		for(j=0;j<len;j++){
			decode_pLMN(&buf[4+index],enb->broadcastpLMNs[i][j],NULL,0);
			index+=3;
		}
		index+=3;
	}
}
void s1ap_decode::decode_ProtocolIE_DefaultPagingDRX(uint8_t* buf,enb_ctx_t* enb){
	if(buf[0]&(1<<7)){
		printf("DefaultPagingDRX: extension field\n");
	}
	int e=(buf[0]&0x60)>>5;
	
}
void s1ap_decode::decode_ProtocolIE_ERAB_SetupListCtxtSURes(uint8_t* buf,erab_setuplistctxtsures_t* est){
	printf("decode protocolIE: buf[0:2]= %02x%02x%02x\n",buf[0],buf[1],buf[2]);
	int len=buf[0]+1;
	//TODO:there's len IEs need to be written
	//if((buf[1]<<8)+buf[2]!=50) printf("error: s1ap_decode: decode_ProtocolIE_ERAB_SetupLIstCtxtSURes: Item unknown\n");
	if(buf[1]!=50) printf("error: s1ap_decode: decode_ProtocolIE_ERAB_SetupLIstCtxtSURes: Item unknown\n");
	//buf[3]: criticality
	//buf[4]: len of E-RABSetupItemCtxtSURes
	//buf[5]&0x80: extension, buf[5]&0x40: preamble, buf[5]&0x20: extension range
	est->ebi = (buf[4]>>1);
	memcpy(&est->enb_ipv4,&buf[6],4);
	memcpy(&est->s1u_enb_fteid,&buf[10],4);
	printf("est: ebi: %d\n enb_ipv4: %08x\n s1u_enb_fteid: %08x\n",est->ebi,est->enb_ipv4,est->s1u_enb_fteid);

}
void s1ap_decode::decode_ProtocolIE_eNB_UE_S1AP_ID(uint8_t* buf,uint32_t* enb_ue_id){
//TODO: find good UE to give eNB and save something for UE?
	int id_enb_ue_s1ap_id=(buf[1]<<8)+buf[2];
	*enb_ue_id = id_enb_ue_s1ap_id;
	printf("enb_ue_s1ap_id: %d\n",*enb_ue_id);
}
void s1ap_decode::decode_ProtocolIE_MME_UE_S1AP_ID(uint8_t* buf,uint32_t* mme_ue_id){
	int len=buf[0],i;
	(*mme_ue_id)=0;
	for(i=0;i<len-1;i++) (*mme_ue_id)+=(((uint32_t)buf[2+i])<<((len-2-i)*8)); 
	printf("mme_ue_id : %08x\n",(*mme_ue_id));
}
void s1ap_decode::decode_ProtocolIE_TAI(uint8_t* buf,enb_ctx_t* enb){
	if(buf[0]&(1<<7)){printf("decode_ProtocolIE_TAI: extension field\n");}
	if(buf[0]&(1<<6)){printf("decode_ProtocolIE_TAI: preamble: iE-Extension exist\n");}
}
void s1ap_decode::decode_InitialUEMessage_ProtocolIE_NAS(uint8_t* buf,ue_ctx_t* ue){
	int len=buf[0];
	m_nas_decode->decode_InitialUEMessage_nas_pdu(&buf[0],&ue->prop);
	ue->sec.ul_count = (ue->prop.msg_type.sr.KSI_and_sequence_number%=32);
}
void s1ap_decode::decode_UplinkNASTransportMessage_ProtocolIE_NAS(uint8_t* buf,UPLINK_NAS_TRANSPORT_STRUCT* nas){
	int len=buf[0];
	m_nas_decode->decode_UplinkNASTransportMessage_nas_pdu(&buf[0],nas);
}
/******************************************************************************
 *									      *
 *			decode ProtocolIE Field				      *
 *									      *
 ******************************************************************************/
int s1ap_decode::decode_S1Setup_ProtocolIE_Field(uint8_t* buf,enb_ctx_t* enb){
	int IEs_ID=(buf[0]<<8)+buf[1],len=buf[3];
	if(IEs_ID==59){			//Global-ENB-ID
		if(buf[2]!=0){printf("#error: id-Global-ENB-ID without criticalty reject\n"); exit(1);}
		decode_ProtocolIE_Global_ENB_ID(buf+4,enb);
	}
	else if(IEs_ID==60){		//eNBname
		if(buf[2]&(1<<6)!=0){printf("#error: id-eNBname without criticalty ignore\n"); exit(1);}
		decode_ProtocolIE_eNBname(buf+4,enb);
	}
	else if(IEs_ID==64){		//SupportedTAs
		if(buf[2]!=0){printf("#error: id-SupportedTAs without criticalty reject\n");exit(1);}
		decode_ProtocolIE_SupportedTAs(buf+4,enb);	
	}
	else if(IEs_ID==0x89){		//DefaultPagingDRX
		if(buf[2]&(1<<6)!=0){printf("#error: id-DefaultPagingDRX without criticalty ignore\n"); exit(1);}
		decode_ProtocolIE_DefaultPagingDRX(buf+4,enb);
	}
	return len;
}
int s1ap_decode::decode_InitialUEMessage_ProtocolIE_Field(uint8_t* buf,ue_ctx_t* ue,uint32_t* enb_ue_id){
	//           Maybe not important except the NAS message 
	int IEs_ID=(buf[0]<<8)+buf[1],len=buf[3];
	if(IEs_ID==8){		//eNB-UE-S1AP-ID
		if(buf[2]!=0){printf("#error: Criticalty error\n");}
		decode_ProtocolIE_eNB_UE_S1AP_ID(buf+4,enb_ue_id);		//TODO: implement
	}
	else if(IEs_ID==26){		//NAS
		if(buf[2]!=0){printf("#error: Criticalty error\n");}
		decode_InitialUEMessage_ProtocolIE_NAS(buf+4,ue);
	}
	else if(IEs_ID==67){		//TAI
		if(buf[2]!=0){printf("#error: Criticalty error\n");}
		decode_ProtocolIE_TAI(buf+4,NULL);			//TODO: implement
	}
	else if(IEs_ID==100){		//ECGI
		
	}
	else if(IEs_ID==134){		//RRC-Establishment-Cause

	}
	else if(IEs_ID==75){		//GUMMEI-ID

	}
	else if(IEs_ID==96){		//S-TMSI
	}

	return len;
}
int s1ap_decode::decode_UplinkNASTransport_ProtocolIE_Field(uint8_t* buf,ue_ctx_t* ue,uint32_t* mme_ue_id,UPLINK_NAS_TRANSPORT_STRUCT* nas){
	int IEs_ID=(buf[0]<<8)+buf[1],len=buf[3];
	printf("IEs_ID: %d\nlen: %d\n",IEs_ID,len);
	if(IEs_ID==0){		//MME-UE-S1AP-ID
		decode_ProtocolIE_MME_UE_S1AP_ID(buf+3,mme_ue_id);
	}
	else if(IEs_ID==8){		//ENB-UE-S1AP-ID
	}
	else if(IEs_ID==26){		//NAS
		decode_UplinkNASTransportMessage_ProtocolIE_NAS(buf+4,nas);
	}
	else if(IEs_ID==100){		//ECGI
	}
	else if(IEs_ID==67){		//TAI
	}
	return len;
}
int s1ap_decode::decode_UEContextReleaseRequest_ProtocolIE_Field(uint8_t* buf,ue_ctx_t* ue){
	
	int IEs_ID=(buf[0]<<8)+buf[1],len=buf[3];
	
	if(IEs_ID==0){		//MME-UE-S1AP-ID
		decode_ProtocolIE_MME_UE_S1AP_ID(buf+3,&ue->MME_UE_ID);
	}
	
	else if(IEs_ID==8){	//ENB-UE-S1AP-ID
		decode_ProtocolIE_eNB_UE_S1AP_ID(buf+4,&ue->eNB_UE_ID);
	}
	
	else if(IEs_ID==2){	//id-cause
	}
	return len;
}
//put mme_ue_s1ap_id and enb_ue_s1ap_id into this function(you can make a struct to save information)
int s1ap_decode::decode_InitialContextSetup_ProtocolIE_Field(uint8_t* buf,erab_setuplistctxtsures_t* est){
        int IEs_ID=(buf[0]<<8)+buf[1],len=buf[3];
		printf("IEs_ID: %d\nlen: %d\n",IEs_ID,len);
        if(IEs_ID==0){          //MME-UE-S1AP-ID
        }
        else if(IEs_ID==8){             //ENB-UE-S1AP-ID
        }
        else if(IEs_ID==51){            //NAS
		//there's something strange
            decode_ProtocolIE_ERAB_SetupListCtxtSURes(buf+5,est);
        }
        return len;
}
/******************************************************************************
 *									      *
 *				decode message				      *
 *									      *
 ******************************************************************************/
void s1ap_decode::decode_s1ap_S1Setup_message(uint8_t* buf,enb_ctx_t* enb){
	int len=buf[0],ProtocolIE_Field_len=((int(buf[2]))<<8)+buf[3],index=0,jndex=0;
//TODO: buf[0]==0x80 => len=((buf[0]&0x3f)<<8)+buf[1];
	if(buf[1]==8){ 
		printf("S1Setup Request Expand\n");
	}
	else {
		for(index=0;index<ProtocolIE_Field_len;index++){
			jndex+=decode_S1Setup_ProtocolIE_Field(buf+jndex+4,enb);
			jndex+=3;
			jndex++;
		}
	}
	if(jndex!=len) printf("jndex : %d, len: %d, different\n",jndex,len);
}
void s1ap_decode::decode_s1ap_InitialUEMessage_message(uint8_t* buf,ue_ctx_t* ue,uint32_t* enb_ue_id){
	int len=buf[0],ProtocolIE_Field_len=((int(buf[2]))<<8)+buf[3],index=0,jndex=0;
	if(buf[0]==0x80){
		len=((buf[0]&0x3f)<<8)+buf[1];
		ProtocolIE_Field_len=((int(buf[3]))<<8)+buf[4];
		index=0;
		jndex=1;
	}
	for(index=0;index<ProtocolIE_Field_len;index++){
		jndex+=decode_InitialUEMessage_ProtocolIE_Field(buf+jndex+4,ue,enb_ue_id);
		jndex+=4;
	}
}
void s1ap_decode::decode_s1ap_UplinkNASTransport_message(uint8_t* buf,ue_ctx_t* ue,uint32_t *mme_ue_s1ap_id,UPLINK_NAS_TRANSPORT_STRUCT* nas){
	int len=buf[0],ProtocolIE_Field_len=((int(buf[2]))<<8)+buf[3],index=0,jndex=0;
	if(buf[0]==0x80){
		len=((buf[0]&0x3f)<<8)+buf[1];
		ProtocolIE_Field_len=((int(buf[3]))<<8)+buf[4];
		index=0;
		jndex=1;
	}
	for(index=0;index<ProtocolIE_Field_len;index++){
	//UE not used?
		jndex+=decode_UplinkNASTransport_ProtocolIE_Field(buf+jndex+4,ue,mme_ue_s1ap_id,nas);
		jndex+=4;
	}
}
void s1ap_decode::decode_s1ap_InitialContextSetup_message(uint8_t* buf,erab_setuplistctxtsures_t* est){
printf("in initialcontext buf[0:2]:%02x%02x%02x\n",buf[0],buf[1],buf[2]);
	int len=buf[0],ProtocolIE_Field_len=((int(buf[2]))<<8)+buf[3],index=0,jndex=0;
	if(buf[0]==0x80){
		len=((buf[0]&0x3f)<<8)+buf[1];
		ProtocolIE_Field_len=((int(buf[3]))<<8)+buf[4];
		index=0;
		jndex=1;
	}
	for(index=0;index<ProtocolIE_Field_len;index++){
	//UE not used?
		jndex+=decode_InitialContextSetup_ProtocolIE_Field(buf+jndex+4,est);
		jndex+=3;
		jndex++;
	}
}
void s1ap_decode::decode_s1ap_UEContextReleaseRequest_message(uint8_t* buf,ue_ctx_t* ue){
	int len=buf[0],ProtocolIE_Field_len=((int(buf[2]))<<8)+buf[3],index=0,jndex=0;
	if(buf[0]==0x80){
		len=((buf[0]&0x3f)<<8)+buf[1];
		ProtocolIE_Field_len=((int(buf[3]))<<8)+buf[4];
		index=0;
		jndex=1;
	}
	for(index=0;index<ProtocolIE_Field_len;index++){
		jndex+=decode_UEContextReleaseRequest_ProtocolIE_Field(buf+jndex+4,ue);
		jndex+=3;
		jndex++;
	}
}
/*
uint8_t c2u(char s){
	if(s>96) return s-87;
	if(s>64) return s-55;
	return s-48;
}
int main(){
	uint8_t code[]="0011003a000004003b00090000f11040fad11010003c4016098041534b4559204c544520536d616c6c2043656c6c004000070000004000f1100089400180";
}
*/
