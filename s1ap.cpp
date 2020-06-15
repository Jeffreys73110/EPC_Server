#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include"s1ap.h"
#include"sec/f1.h"

s1ap* s1ap::m_instance=NULL;
pthread_mutex_t s1ap_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

s1ap::s1ap(){

}
/*enb_ctx_t* s1ap::add_new_enb_ctx_t(){
	//TODO: new enb
	if(enb_list==NULL) enb_list = new enb_ctx_t();
	return enb_list;
}*/
ue_ctx_t* s1ap::add_new_ue_ctx_t(){
	//TODO: new ue
	if(ue_list==NULL) ue_list = new ue_ctx_t();
	return ue_list;
}
s1ap* s1ap::get_instance(){
	pthread_mutex_lock(&s1ap_instance_mutex);
	if(m_instance==NULL){
		m_instance = new s1ap();
	}
	pthread_mutex_unlock(&s1ap_instance_mutex);
	return m_instance;
}
ue_ctx_t* s1ap::find_ue_by_mme_ue_s1ap_id(uint32_t mme_ue_s1ap_id){
	//TODO: find by mme_ue_s1ap_id
	return ue_list;
}
int s1ap::get_next_mme_ue_id(){
	return m_mme_ue_s1ap_id++;
}
int s1ap::get_next_ctrl_fteid(){
	//return m_mme_global_ctrl_fteid++;
	return m_mme_global_ctrl_fteid;
}
uint32_t s1ap::get_next_ue_ipv4(){
	//FIXME: use ip pool instead of just increasing 1
	uint32_t ue_ipv4 = m_ue_ipv4;
	m_ue_ipv4 = ntohl(htonl(ue_ipv4)+1);
	return ue_ipv4;
}
uint32_t s1ap::get_spgw_addr_ipv4(){
	return m_spgw_addr_ipv4;
}
uint32_t s1ap::get_next_pdn_ipv4(){
	return m_ue_ipv4++;
}
int s1ap::find_eNB_by_IP(char* IP){
	int i;
	for(i=0;i<eNB_NUM;i++){
		if(!strcmp(eNB_LIST[i].IP,IP))
			break;
	}
	if(i==eNB_NUM)//Not found
		return -1;
	else 
		return i;
}
void s1ap::get_next_guti(NAS_EPS_MOBILE_ID_GUTI_STRUCT* guti){
	//FIXME: use guti pool 
	memcpy(guti,&m_next_guti,sizeof(NAS_EPS_MOBILE_ID_GUTI_STRUCT));
}
void s1ap::init(){
//TODO: set more things to next_guti
	eNB_NUM=0;
	m_next_guti.m_tmsi = 0x5a3148ce;
	m_mme_ue_s1ap_id = 3410577134;
	m_ue_ipv4 = inet_addr("192.168.200.1");
	m_spgw_addr_ipv4=inet_addr("10.102.81.102");
	m_spgw = spgw::get_instance();
	//m_spgw->init();	// The init() function is already put in get_instance() function
	m_s1ap_decode = s1ap_decode::get_instance();
	m_s1ap_decode->init();
	m_s1ap_encode = s1ap_encode::get_instance();
	m_s1ap_encode->init();
	s1ap_args = new s1ap_args_t();
	
	m_mme_global_ctrl_fteid = 0x01000000;
	strcpy(s1ap_args->MMEname,"mmec01.mmegi8000.mme.epc.mnc001.mcc001.3gppnetwork.org");
	strcpy(s1ap_args->Served_pLMN[0],"00f110");
	s1ap_args->len_ServedGUMMEIs = 1;
	s1ap_args->len_ServedpLMNs = 1;	//TODO: change to len_ServedGUMMEIs length array
	s1ap_args->len_ServedGroupID = 1;
	s1ap_args->len_ServedMMECs = 1;
	s1ap_args->Served_MME_Group_ID[0] = 32768;	//TODO: the same
	s1ap_args->Served_MME_Code[0] = 1;		//TODO: the same
	s1ap_args->RelativeMMECapacity = 1;
}
//FIXME: all the functions that have "ue_ctx_t" struct as input should be inputed with the ue that found by
//       mme_ue_s1ap_id and enb_ue_s1ap_id
int s1ap::decode_s1ap_initiating_message(char* eNB_IP,uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT* next_message){
	// S1Setup
	if(buf[0]==0x11){
		enb_ctx_t temp_enb;
		if(buf[1]!=0) {printf("#error: S1Setup without criticalty reject\n"); exit(1);}
		m_s1ap_decode->decode_s1ap_S1Setup_message(buf+2,&temp_enb);
		temp_enb.UE_NUM=0;
		strcpy(temp_enb.IP,eNB_IP);
		//TODO: use temp_enb's properties to check whether it exists in the list
		//	and make it a list
		//enb_list = add_new_enb_ctx_t();
		//memcpy(enb_list,&temp_enb,sizeof(enb_ctx_t));
		//enb_list->print_properties();
		
		//Add the latest eNB to eNB_LIST
		memcpy(&eNB_LIST[eNB_NUM],&temp_enb,sizeof(enb_ctx_t));
		eNB_LIST[eNB_NUM].print_properties();
		eNB_NUM++;
		printf("There's total %d eNB under MME",eNB_NUM);
		
		//TODO: check success/fail flag
		return m_s1ap_encode->encode_S1Response_message(sendbuf,s1ap_args);
	}

	// Initial UE Message
	else if(buf[0]==0x0c){
		if(buf[1]!=0x40){printf("#error: InitialUEMessage with wrong criticalty\n"); exit(1);}
		//ue_ctx_t temp_ue;
		uint32_t enb_ue_id,mme_ue_id;
		ue_ctx_t *ue = add_new_ue_ctx_t();
		m_s1ap_decode->decode_s1ap_InitialUEMessage_message(buf+2,ue,&ue->eNB_UE_ID);
		printf("ue->sec.k_enb:%x %x %x\n",ue->sec.k_enb[0],ue->sec.k_enb[1],ue->sec.k_enb[2]);
		//m_s1ap_decode->decode_s1ap_InitialUEMessage_message(buf+2,&temp_ue,&temp_ue.eNB_UE_ID);
		//memcpy(ue,&temp_ue,sizeof(ue_ctx_t));

		ue->MME_UE_ID = m_mme_ue_s1ap_id;	//return current mme_ue_s1ap_id
		//ue->init();
//Delete this after debugging
//ue->MME_UE_ID=get_next_mme_ue_id(); ue->eNB_UE_ID=1;
//TODO: not give ue_list but give right ue to encode initialUEMessage
printf("ue eps_mobile_id_type: %02x\n",ue->prop.msg_type.ar.eps_mobile_id.type);

		//attach request
		if(ue->prop.request_type==0x41){
			// GUTI
			//TODO: not just send Identity Request but find all ue with guti
			//ue->MME_UE_ID = get_next_mme_ue_id();
			if(ue->prop.msg_type.ar.eps_mobile_id.type == 6){	
				return m_s1ap_encode->encode_Identity_Request_message(sendbuf,&ue->MME_UE_ID,&ue->eNB_UE_ID);
			}

			// IMSI
			else if(ue->prop.msg_type.ar.eps_mobile_id.type==1){
				return m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);
			}
			else
				return m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);
		}
		//service request (Reserved 0)
		else if(ue->prop.request_type==0){
			uint32_t s11_sgw_fteid,s1u_sgw_fteid;
			
			printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\ncreate session request\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
			m_spgw->manage_create_session_request(get_next_ctrl_fteid(),5,9,&s11_sgw_fteid,&s1u_sgw_fteid);
			ue->erab[5].s11_sgw_fteid = s11_sgw_fteid;
			ue->erab[5].s11_mme_fteid = get_next_ctrl_fteid();
			ue->erab[5].s1u_sgw_fteid = s1u_sgw_fteid;
			ue->erab[5].pdn_ipv4 = get_next_pdn_ipv4();
			ue->erab[5].pdn_ipv4 = m_ue_ipv4-1;
			ue->erab[5].s1u_ipv4 = get_spgw_addr_ipv4();
			
			//get_next_guti(&ue->prop.msg_type.ar.eps_mobile_id.guti);
			
			return m_s1ap_encode->encode_InitialContextSetupRequest_UECapabilityInformation_message(sendbuf,ue);
		}
			return -1;
	}

	//Uplink NAS Transport
	else if(buf[0]==0x0d){
		if(buf[1]!=0x40){printf("#error: UplinkNASTransport with wrong criticalty\n");}
		uint32_t mme_ue_s1ap_id = 0;
		ue_ctx_t ue;			//ue : Not used
		UPLINK_NAS_TRANSPORT_STRUCT nas;
		m_s1ap_decode->decode_s1ap_UplinkNASTransport_message(buf+2,&ue,&mme_ue_s1ap_id,&nas); // ue: Not used
		ue_ctx_t* temp_ue = find_ue_by_mme_ue_s1ap_id(mme_ue_s1ap_id);

		// identity response
		if(nas.request_type==0x56){
//Delete this after debugging
//temp_ue=new ue_ctx_t(); temp_ue->MME_UE_ID=get_next_mme_ue_id(); temp_ue->eNB_UE_ID=1;
			memcpy(&temp_ue->prop.msg_type.ar.eps_mobile_id,&nas.prop.id,sizeof(temp_ue->prop.msg_type.ar.eps_mobile_id));
			return m_s1ap_encode->encode_Authentication_Request_message(sendbuf,temp_ue);
		}
		// Authentication failure
		if(nas.request_type==0x5c){
			// Synch failure
			if(nas.prop.af.emm_cause==21){
				resync(nas.prop.af.sqn_ms_xor_ak,temp_ue->sec.rand,temp_ue->sec.sqn);
				return m_s1ap_encode->encode_Authentication_Request_message(sendbuf,temp_ue);
			}
		}
		// Authentication Response
		if(nas.request_type==0x53){
			int i;
			for(i=0;i<8;i++) if(temp_ue->sec.res[i]!=nas.prop.res.res[i]) printf("security: ue res error\n");
			//TODO: res error
			//TODO: choose EIA EEA here
			temp_ue->sec.dl_count = 0;
			temp_ue->sec.ul_count = 0;
			temp_ue->sec.int_al = 1;
			temp_ue->sec.enc_al = 0;
			init_k_int_enc(temp_ue->sec.k_asme,temp_ue->sec.k_nasint,temp_ue->sec.k_nasenc,1,0);
			return m_s1ap_encode->encode_Security_Mode_Command_message(sendbuf,temp_ue);
		}
		//Security Mode Complete
		//TODO: all *if* after Security Mode Complete should check int and enc
		if(nas.request_type==0x5e){
			printf("dl_count: %d\n",temp_ue->sec.dl_count);
			return m_s1ap_encode->encode_ESM_Information_Request_message(sendbuf,temp_ue);
		}
		//ESM Mode response
		if(nas.request_type==0xda){
			if(nas.prop.esm_info.len>40) printf("ESM Mode response error: apn name len>40\n");
			memcpy(temp_ue->prop.msg_type.ar.apn_name,nas.prop.esm_info.apn_name,nas.prop.esm_info.len);
			temp_ue->prop.msg_type.ar.apn_len = nas.prop.esm_info.len;
			next_message->type = 9;
			next_message->temp_ue = temp_ue;
			return m_s1ap_encode->encode_EMM_Information_Request_message(sendbuf,temp_ue);
		}
	}
	
	//UEContextReleaseRequest
	else if(buf[0]==0x12){
		if(buf[1]!=0x40){printf("#error: UEContextReleaseRequest with wrong criticalty\n");}
		
		//ue_ctx_t temp_ue;
		
		//m_s1ap_decode->decode_s1ap_UEContextReleaseRequest_message(buf+2,&temp_ue);
		
		
		ue_ctx_t *ue = add_new_ue_ctx_t();
		m_s1ap_decode->decode_s1ap_UEContextReleaseRequest_message(buf+2,ue);
		
		//memcpy(ue,&temp_ue,sizeof(ue_ctx_t));
		
		//Fixme: find session by UE but not constant
		//m_spgw->manage_end_session_request(m_mme_global_ctrl_fteid);
		
		return m_s1ap_encode->encode_UEContextReleaseCommand_message(sendbuf,ue);
	}
	return -1;
}
int s1ap::decode_s1ap_successfulOutcome_message(char* eNB_IP,uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT* next_message){
	//InitialContextSetupResponse
	if(buf[0]==0x09){
		//FIXME: extract mme_ue_s1ap_id and find by it
		uint32_t mme_ue_s1ap_id;
		ue_ctx_t* ue = find_ue_by_mme_ue_s1ap_id(mme_ue_s1ap_id);
		erab_setuplistctxtsures_t est;
		m_s1ap_decode->decode_s1ap_InitialContextSetup_message(buf+2,&est);
		m_spgw->manage_modify_bearer_request(ue->erab[5].s11_sgw_fteid,est);
		
		
		int index = find_eNB_by_IP(eNB_IP);
		eNB_LIST[index].UE_LIST[eNB_LIST[index].UE_NUM]=mme_ue_s1ap_id;
		eNB_LIST[index].UE_NUM++;
		eNB_LIST[index].print_properties();
	}
	return -1;
}

int s1ap::decode_s1ap_UnsuccessfulOutcome_message(uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT* next_message){
	//InitialContextSetupFailure
	if(buf[0]==0x09){
		
	}
	return -1;
}
// Next message is used for the situation that you should send two consecutive message.
// Struct next_message may need to save informations other than 9(Initial Context Setup Request)
// Such as Attach Accept, Activate default EPS bearer context request
int s1ap::handle_s1ap_pdu(char* eNB_IP,uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT* next_message){
	// FIXME: this should be packed as a function for the readability
	if(next_message->type>0){

		//id InitialContextSetupRequest
		if(next_message->type == 9){
			//reset type
			// don't put this outside the if above
			next_message->type = -1;

			// Create Session Request, you can receive some information here
			uint32_t s11_sgw_fteid,s1u_sgw_fteid;
printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\ncreate session request\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

			m_spgw->manage_create_session_request(get_next_ctrl_fteid(),5,9,&s11_sgw_fteid,&s1u_sgw_fteid);

			// FIXME: erab_id maybe not be only 5 here
			next_message->temp_ue->erab[5].s11_sgw_fteid = s11_sgw_fteid;
			next_message->temp_ue->erab[5].s11_mme_fteid = get_next_ctrl_fteid();
			next_message->temp_ue->erab[5].s1u_sgw_fteid = s1u_sgw_fteid;
			next_message->temp_ue->erab[5].pdn_ipv4 = get_next_pdn_ipv4();
			next_message->temp_ue->erab[5].s1u_ipv4 = get_spgw_addr_ipv4();

			get_next_guti(&next_message->temp_ue->prop.msg_type.ar.eps_mobile_id.guti);

			return m_s1ap_encode->encode_InitialContextSetupRequest_message(sendbuf,next_message->temp_ue,5);
		}
	}
	else if(buf[0]&(1<<7)){
		printf("Extern Message(Initiating)\n");
	}
	else{
		if(buf[0]&(1<<6)){
			printf("UnsuccessfulOutcome\n");
			return decode_s1ap_UnsuccessfulOutcome_message(buf+1,sendbuf,next_message);
		}
		else if(buf[0]&(1<<5)){
			printf("\nSuccessfulOutcome\n");
			return decode_s1ap_successfulOutcome_message(eNB_IP,buf+1,sendbuf,next_message);
		}
		else{
			printf("\nInitiating\n");
			return decode_s1ap_initiating_message(eNB_IP,buf+1,sendbuf,next_message);
		}
	}
	return -1;
}
/*
int main(){
	char c[]="000d403e00000500000005c0d24495f600080002002c001a001211175741cf28060756080910101032540606006440080000f110fad11010004340060000f1100001";
	char sssc[]="000b403b00000300000005c0c2f54544000800020001001a002524075200cb67060000000000cb670600000000001015f5429b51a58000e5f3dc9c1d5725e6";
	uint8_t d[500];
	uint8_t ss[500],sss[500];
	
	int i;
	for(i=0;i<500;i++){
		d[i]=(c2u(c[i*2])<<4)+(c2u(c[i*2+1]));
		sss[i]=(c2u(sssc[i*2])<<4)+(c2u(sssc[i*2+1]));
	}
	s1ap* m_s1ap;
	m_s1ap=s1ap::get_instance();
	m_s1ap->init();
	m_s1ap->handle_s1ap_pdu(d,ss);
printf("compare output: \n");
	for(i=0;i<63;i++) printf("%02x",ss[i]);
	printf("\n%s\n",sssc);
}*/
