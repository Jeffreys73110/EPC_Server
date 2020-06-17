#include<stdio.h>
#include<stdlib.h>
#include<memory.h>
#include<pthread.h>

#include"nas_decode.h"
#include"nas_common.h"

/***********************************************************************
	TODO:   Give Length to decode every message or it may
		ommit Segmentation Fault
***********************************************************************/
nas_decode* nas_decode::m_instance=NULL;
pthread_mutex_t nas_decode_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

nas_decode::nas_decode(){

}
nas_decode* nas_decode::get_instance(){
	pthread_mutex_lock(&nas_decode_instance_mutex);
	if(m_instance==NULL){
		m_instance=new nas_decode();
	}
	pthread_mutex_unlock(&nas_decode_instance_mutex);
	return m_instance;
}
int nas_decode::decode_message_type_pos(uint8_t* msg, int* sec_header, int* pd){//24.301 9.1
	*sec_header=(msg[0]&0xf0)>>4;
	*pd=msg[0]&0x0f;
	
	// Service Request
	if(*sec_header==12)
	{
		//TODO: return service_request
		return 0;
	}
	else
	{
		// ESM
		if(*pd==2)
			return 2;		//ESM Message will have Procedure transaction identity(non-protected)
		else{
			if(*sec_header==0)
				return 1;	//EMM(non-protected)
			else{				
				*pd=msg[6]&0x0f;
				if(*pd==2)
					return 8;//ESM Message will have Procedure transaction identity(protected)
				else
					return 7;//EMM(protected)
			}
		}
	}
	return -1;
}
void nas_decode::decode_eps_attach_type(uint8_t* msg,int pos,uint8_t* re){//24.301  9.9.3.11
	(*re)=((*msg)>>pos)&0x7;
}
void nas_decode::decode_nas_key_set_id(uint8_t* msg,int pos,NAS_NAS_KEY_SET_ID_STRUCT* re){//24.301  9.9.3.21
	re->tsc=((*msg)>>pos)&0x8;		//type of security context
	re->nas_ksi=((*msg)>>pos)*0x7;  //NAS key set identifier
}
void nas_decode::decode_eps_mobile_id(uint8_t* msg,NAS_EPS_MOBILE_ID_STRUCT* re,int* len){//24.301 9.9.3.12
	int type=msg[1]&0x7,i;
	bool is_odd=msg[1]&0x8;
	re->type=type;

	*len=msg[0];
	
	// IMSI
	if(type==1){
		if(is_odd){
			re->imsi[0]=((msg[1]&0xf0)>>4);
			for(i=2;i<=*len;i++){
				re->imsi[i*2-2]=((msg[i]&0xf0)>>4);
				re->imsi[i*2-3]=(msg[i]&0x0f);
			}
		}
		else{
			for(i=1;i<*len;i++){
				re->imsi[i*2-2]=((msg[i]&0xf0)>>4);
				re->imsi[i*2-1]=(msg[i+1]&0x0f);
			}
		}
	}
	
	// GUTI
	else if(type==6){
		re->guti.mcc=((msg[2]&0x0f)<<8)+(msg[2]&0xf0)+(msg[3]&0x0f);
		re->guti.mnc=((msg[4]&0x0f)<<8)+(msg[4]&0xf0)+((msg[3]&0xf0)>>4);
		re->guti.mmegi=(msg[5]<<8)+msg[6];
		re->guti.mmec=msg[7];
		re->guti.m_tmsi=0;
		for(i=0;i<4;i++){
			re->guti.m_tmsi+=(msg[8+i]<<(8*(3-i)));
		}
	}

	// IMEI
	else if(type==3){
		if(is_odd){
			re->imei[0]=((msg[1]&0xf0)>>4);
			for(i=2;i<=*len;i++){
				re->imei[i*2-2]=((msg[i]&0xf0)>>4);
				re->imei[i*2-3]=(msg[i]&0x0f);
			}
		}
		else{
			for(i=1;i<*len;i++){
				re->imei[i*2-2]=((msg[i]&0xf0)>>4);
				re->imei[i*2-1]=(msg[i+1]&0x0f);
			}
		}
	}
	else{ printf("nas_decode::decode_eps_mobile_id: decode error\n"); }
	(*len)++;
}
void nas_decode::decode_ue_network_capability(uint8_t* msg,NAS_UE_NETWORK_CAPABILITY_STRUCT* re,int* len){//24.301 9.9.3.34
	*len=msg[0];
	int i;
	for(i=0;i<8;i++){
		re->eea[i]=(msg[1]&(1<<(7-i)));
		if(*len>1)
			re->eia[i]=(msg[2]&(1<<(7-i)));
		if(*len>2)
			re->uea[i]=(msg[3]&(1<<(7-i)));
		if(*len>3)
			if(i==0)
				re->ucs2=(msg[4]&(1<<7));
			else
				re->uia[i]=(msg[4]&(1<<(7-i)));
	}
	(*len)++;
}
void nas_decode::decode_esm_information_transfer_flag(uint8_t* msg,bool* eit,int* index){//24.301 9.9.4.5
	*eit=(msg[0]&0x01);
	(*index)++;
}
void nas_decode::decode_protocol_configuration_options(uint8_t* msg,NAS_PROTOCOL_CONFIGURATION_STRUCT* cfg,int* index){
	int len=msg[0],jndex=2;

	// Pass msg[1] for constant input (in this version of 3GPP TS 24.008)

	for(;jndex<len;){
		cfg->id=(msg[jndex]<<8)+msg[jndex+1];
		cfg->len=msg[jndex+2];
		memcpy(cfg->contents,&msg[jndex+3],cfg->len);
		jndex+=cfg->len+3;
		cfg++;
	}

	*index+=jndex;
}
void nas_decode::decode_pdn_connectivity_request(uint8_t* msg,NAS_PDN_CONNECTIVITY_REQUEST_STRUCT* pdn,int* len){//24.301 9.9.3.15 -> 8.3.1.1
	*len=(msg[0]<<8)+msg[1];

	// EPS Bearer ID 24.301 9.3.2
	pdn->eps_bearer_id=((msg[2]&0xf0)>>4);

	// Procedure Transaction ID 24.301 9.4
	pdn->procedure_transaction_id=msg[3];

	// Request Type 24.301 9.8 -> 8.3.20
	if(msg[4]!=0xd0) printf("decode_pdn_connectivity_request: id is not PDN CONNECTIVITY REQUEST!!");

	// PDN Type 24.301 9.9.4.10
	pdn->pdn_type=((msg[5]&0xf0)>>4);

	// Request type 24.301 9.9.4.14 -> 24.008 10.5.6.17
	pdn->request_type=(msg[5]&0x0f);
	
	int index=6;
	/*
	for(;index<*len;){
		// EIT (ESM information transfer flag)
		if(((msg[index]&0xf0)>>4)==0xd){
			decode_esm_information_transfer_flag(&msg[index],&pdn->eit,&index);
		}

		// Protocol Configuration Options
		else if(msg[index]==0x27){
			decode_protocol_configuration_options(&msg[index+1],pdn->opt,&index);
		}

		else{
			printf("decode_pdn_connectivity_request: unknow element id(TODO)\n");
			break;
		}
	}
	*/
	(*len)+=2;
}
void nas_decode::decode_last_visited_registered_tai(uint8_t* msg,NAS_TRACKING_AREA_ID_STRUCT* tai,int* len){//24.301 9.9.3.32
	tai->mcc=((msg[0]&0x0f)<<8)+(msg[0]&0xf0)+(msg[1]&0x0f);
	tai->mnc=((msg[2]&0x0f)<<8)+(msg[2]&0xf0)+((msg[1]&0xf0)>>4);
	tai->tac=(msg[3]<<8)+msg[4];
	printf("mcc:%03x,mnc:%03x,tai:%x\n",tai->mcc,tai->mnc,tai->tac);
	*len=5;
}
void nas_decode::decode_drx_parameter(uint8_t* msg,NAS_DRX_PARAMETER_STRUCT* drx,int* len){//24.008 10.5.5.6
	drx->split_pg_cycle_code=msg[0];
	drx->drx_cycle_length_coeff_and_value=((msg[1]&0xf0)>>4);
	drx->split_on_ccch=((msg[1]&0x80)>>3);
	drx->non_drx_time=(msg[1]&0x7);
	*len=2;
//printf("split:%x,dclcav:%x,soc:%x,ndt:%x\n",drx->split_pg_cycle_code,drx->drx_cycle_length_coeff_and_value,drx->split_on_ccch,drx->non_drx_time);
}
void nas_decode::decode_ms_network_capability(uint8_t* msg,NAS_MS_NETWORK_CAPABILITY_VALUE_STRUCT* ms_net_cap,int* len){//24.008 10.5.5.12
	int i;
	ms_net_cap->gea[1]=((msg[1]&0x80)>>7);
	ms_net_cap->sm_via_ded=((msg[1]&0x40)>>6);
	ms_net_cap->sm_via_gprs=((msg[1]&0x20)>>5);
	ms_net_cap->ucs2=((msg[1]&0x10)>>4);
	ms_net_cap->ss_screen_indicator=((msg[1]&0xc)>>2);
	ms_net_cap->solsa=((msg[1]&0x02)>>1);
	ms_net_cap->revision=((msg[1]&0x01));
	
	ms_net_cap->pfc=((msg[2]&0x80)>>7);
	for(i=1;i<=6;i++)
		ms_net_cap->gea[i+1]=((msg[2]&(1<<(7-i)))>>(7-i));
	
	ms_net_cap->lcsva=((msg[2]&0x01));

	ms_net_cap->ho_g2u_iu=((msg[3]&0x80)>>7);
	ms_net_cap->ho_g2e_s1=((msg[3]&0x40)>>6);
	ms_net_cap->emm_com=((msg[3]&0x20)>>5);
	ms_net_cap->isr=((msg[3]&0x10)>>4);
	ms_net_cap->srvcc=((msg[3]&0x08)>>3);
	ms_net_cap->epc=((msg[3]&0x04)>>2);
	ms_net_cap->nf=((msg[3]&0x02)>>1);
	ms_net_cap->geran=((msg[3]&0x01));
	*len=msg[0]+1;
	if(*len>4)
		printf("decode_ms_network_capability: there's more things in this function should be decode\n");
//TODO: not debugged
//TODO: maybe more things
}
void nas_decode::decode_tmsi_status(uint8_t* msg,int pos,bool* flag){//24.008 10.5.5.4
	*flag=((msg[0]>>pos)&0x01);
}
void nas_decode::decode_mobile_station_classmark2(uint8_t* msg,NAS_MS_CLASSMARK2_STRUCT* ms_cm2,int* len){//24.008 10.5.1.6
	*len=msg[0];
	if(*len!=3){printf("decode_mobile_station_classmark2 error: length not match\n");}
	ms_cm2->revision=((msg[1]&0x60)>>5);
	ms_cm2->esing=((msg[1]&0x10)>>4);
	ms_cm2->a5_1=((msg[1]&0x08)>>3);
	ms_cm2->rf_power_cap=(msg[1]&0x07);
	
	ms_cm2->ps_cap=((msg[2]&0x40)>>6);
	ms_cm2->ss_screen_indicator=((msg[2]&0x30)>>4);
	ms_cm2->sm_cap=((msg[2]&0x08)>>3);
	ms_cm2->vbs=((msg[2]&0x04)>>2);
	ms_cm2->vgcs=((msg[2]&0x02)>>1);
	ms_cm2->fc=((msg[2]&0x01));

	ms_cm2->cm3=((msg[3]&0x80)>>7);
	ms_cm2->lcsva=((msg[3]&0x20)>>5);
	ms_cm2->ucs2=((msg[3]&0x10)>>4);
	ms_cm2->solsa=((msg[3]&0x08)>>3);
	ms_cm2->cmsp=((msg[3]&0x04)>>2);
	ms_cm2->a5_3=((msg[3]&0x02)>>1);
	ms_cm2->a5_2=((msg[3]&0x01));
//TODO: not debugged
}
void nas_decode::decode_voice_domain_pref_and_ue_usage_setting_value(uint8_t* msg, NAS_VOICE_DOMAIN_PREF_AND_UE_USAGE_SETTING_VALUE_STRUCT* value,int* len){//24.008 10.5.5.28
	*len=msg[0];
	value->voice_domain_pref=msg[1]&0x03;
	value->ue_usage_setting_value=(msg[1]&0x04)>>2;
}
void nas_decode::decode_guti_type(uint8_t* msg, int pos,bool* type){//24.301 9.9.3.45
	*type=((msg[0]>>pos)&0x01);
}
void nas_decode::decode_attach_request(uint8_t* msg,NAS_ATTACH_REQUEST_STRUCT* nas){//24.301  8.2.4
	int len;
	
	// EPS Attach Type
	decode_eps_attach_type(msg,0,&nas->eps_attach_type);

	// NAS Key Set ID
	decode_nas_key_set_id(msg,4,&nas->nas_ksi);
	msg++;

	// EPS Mobile ID
	decode_eps_mobile_id(msg,&nas->eps_mobile_id,&len);
	msg+=len;

	// UE Network Capability
	decode_ue_network_capability(msg,&nas->ue_cap,&len);
	msg+=len;

	// PDN Connectivity Request (in ESM Message Container)
	decode_pdn_connectivity_request(msg,&nas->pdn_con_request,&len);
	msg+=len;

	// Tracking Area ID (TAI)
	if(*msg==0x52){
		msg++;
		decode_last_visited_registered_tai(msg,&nas->last_visited_registered_tai,&len);
		nas->last_visited_registered_tai_present=true;
		msg+=len;
	}
	// DRX Parameter
	if(*msg==0x5c){
		msg++;
		decode_drx_parameter(msg,&nas->drx_param,&len);
		nas->drx_param_present=true;
		msg+=len;
	}
	// MS Network Capability
	if(*msg==0x31){
		msg++;
		decode_ms_network_capability(msg,&nas->ms_net_cap,&len);
		nas->ms_net_cap_present=true;
		msg+=len;
	}
	// TMSI status
	if(((*msg)&0xf0)==0x90){
		decode_tmsi_status(msg,0,&nas->tmsi_flag);
		nas->tmsi_flag_present=true;
		msg++;
	}
	// MS Mobile Station classmark2
	if(*msg==0x11){
		msg++;
		decode_mobile_station_classmark2(msg,&nas->ms_cm2,&len);
		nas->ms_cm2_present=true;
		msg+=len;
		msg++;
	}
	// Voice Domain Preference and UE Usage Setting Value
	if(*msg==0x5d){
		msg++;
		decode_voice_domain_pref_and_ue_usage_setting_value(msg,&nas->voice_domain_pref_and_ue_usage_setting_value,&len);
		msg+=len;
		msg++;
	}
	// GUTI Type
	if(((*msg)&0xf0)==0xe0){
		decode_guti_type(msg,0,&nas->guti_type);
		msg++;
	}
//TODO: There should be more IEs in this ATTACH REQUEST(see nas_common.h)
}
void nas_decode::decode_identity_response(uint8_t* msg,NAS_EPS_MOBILE_ID_STRUCT* eps_mobile_id){//24.008 10.5.1.4
	int len;

	// EPS Mobile ID
	decode_eps_mobile_id(&msg[0],eps_mobile_id,&len);
}
void nas_decode::decode_EMM_cause(uint8_t* msg,int* emm_cause){
	*emm_cause=msg[0];
}
void nas_decode::decode_Authentication_failure_Parameter(uint8_t* msg,UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT* nas){
	memcpy(nas->sqn_ms_xor_ak,&msg[0],6);
	memcpy(nas->mac_s,&msg[6],8);
}
void nas_decode::decode_Authentication_failure(uint8_t* msg,UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT* nas){
	//TODO: return synch failure or other failures

	decode_EMM_cause(&msg[0],&nas->emm_cause);
	//msg[1] for element id of 
	//msg[2] for length
	if(nas->emm_cause==21&&msg[1]==0x30)	//0x30: synch failure
		decode_Authentication_failure_Parameter(&msg[3],nas);
}
void nas_decode::decode_Authentication_response(uint8_t* msg,UPLINK_NAS_TRANSPORT_AUTHENTICATION_RESPONSE_STRUCT* nas){
	//msg[0]: length
	memcpy(nas->res,&msg[1],8);
}
void nas_decode::decode_ESM_information_response(uint8_t* msg,UPLINK_NAS_TRANSPORT_ESM_INFORMATION_RESPONSE_STRUCT* nas){
	//TODO: other optional IE
	if(msg[0]==0x28){
		nas->len=msg[1];
		memcpy(nas->apn_name,&msg[2],nas->len);
	}
}
void nas_decode::decode_service_request(uint8_t* msg,NAS_SERVICE_REQUEST_STRUCT* sr){
	sr->KSI_and_sequence_number=msg[1];
}
void nas_decode::decode_InitialUEMessage_nas_pdu(uint8_t* msg,NAS_INITIAL_UE_MESSAGE_STRUCT* prop){
	int header,pd,len=msg[0];
	int pos=decode_message_type_pos(&msg[1],&header,&pd);
	prop->request_type=msg[pos+1];
	
	//service request
	if(pos==0){
		prop->request_type=0; //serivce request (Reserved 0)
		decode_service_request(&msg[1],&prop->msg_type.sr);
	}
	
	// Attach Request
	else if(prop->request_type==0x41)
	{
		decode_attach_request(&msg[pos+2],&prop->msg_type.ar);
	}
	
	//Tracking Area Update Request
	if(prop->request_type==0x48)
	{
		
	}
}
void nas_decode::decode_UplinkNASTransportMessage_nas_pdu(uint8_t* msg,UPLINK_NAS_TRANSPORT_STRUCT* nas){
	int header,pd,len=msg[0];
	int pos=decode_message_type_pos(&msg[1],&header,&pd);
	nas->request_type=msg[pos+1];
	
	//Identity Response
	if(nas->request_type==0x56){
		decode_identity_response(&msg[pos+2],&nas->prop.id);
	}

	//Authentication Failure
	if(nas->request_type==0x5c){
		decode_Authentication_failure(&msg[pos+2],&nas->prop.af);
	//TODO: return synch failure or other failures
	}

	//Authentication Response
	if(nas->request_type==0x53){
		decode_Authentication_response(&msg[pos+2],&nas->prop.res);
	}

	//Security Mode Complete
	if(nas->request_type==0x5e){
		if(len!=8){
			//TODO: decode Security Mode's Optional things
		}
	}

	//ESM information Response
	if(nas->request_type==0xda){
		decode_ESM_information_response(&msg[pos+2],&nas->prop.esm_info);
	}
	
	//Tracking Area Update Request
	if(nas->request_type==0x48){
		
	}
	
	//PDN Connectivity Request
	if(nas->request_type==0xd0){

	}
	
	printf("\n");
}
/*
uint8_t c2u(char c){
	if(c>96)
	return c-87;
	else
	return c-48;
}

int main(){
	char c[]="17cac9073d050741020bf600f110800001d24495f604e060c04000210201d011d1271a8080211001000010810600000000830600000000000d00000a005200f11000015c0a003103e5e0349011035758a65d0100e0";
	uint8_t d[86];
	for(i=0;i<86;i++){
		d[i]=(c2u(c[i*2])<<4)+(c2u(c[i*2+1]));
	}
	decode_nas_pdu(d);
}

*/
