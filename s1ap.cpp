#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include"s1ap.h"
#include"sec/f1.h"
#include <unistd.h>

s1ap* s1ap::m_instance=NULL;
pthread_mutex_t s1ap_instance_mutex=PTHREAD_MUTEX_INITIALIZER;

s1ap::s1ap(){
	eRabSetup_dedicated_flag = false;
	memset(ue_list, 0, sizeof(ue_list));
	ue_List_num = 0;
}
ue_ctx_t* s1ap::add_new_ue_ctx_t(){
	LINE_TRACE();
	//TODO: new ue

	int cur;
	for (cur=0; cur<UE_LIST_SIZE; cur++)
	{
		if (ue_list[cur]==NULL) 
		{
			LINE_TRACE();
			if (ue_list[cur] = new ue_ctx_t())
				ue_List_num++;
			TestMsg_TRACE("ue_list[%d]=0x%x\n", cur, ue_list[cur]);
			break;
		}
	}
	if (cur >= UE_LIST_SIZE)	{ RETURN NULL; printf("ue_list is full\n"); }
	RETURN ue_list[cur];
}

int s1ap::set_inital_ue_ctx_t(ue_ctx_t *ue)
{
	LINE_TRACE();
	if (!ue)	{RETURN -1;}

	//--- set ue context
	ue->MME_UE_ID = get_next_mme_ue_id();
	TestMsg_TRACE("ue=0x%x, ue->MME_UE_ID=0x%x\n", ue, ue->MME_UE_ID);
	//
	ue->prop.msg_type.ar.ue_cap.eea[0] = 1;
	ue->prop.msg_type.ar.ue_cap.eea[1] = 1;
	ue->prop.msg_type.ar.ue_cap.eea[2] = 1;
	ue->prop.msg_type.ar.ue_cap.eea[3] = 1;
	ue->prop.msg_type.ar.ue_cap.eea[4] = 0;
	ue->prop.msg_type.ar.ue_cap.eea[5] = 0;
	ue->prop.msg_type.ar.ue_cap.eea[6] = 0;
	ue->prop.msg_type.ar.ue_cap.eea[7] = 0;
	//
	ue->prop.msg_type.ar.ue_cap.eia[0] = 1;
	ue->prop.msg_type.ar.ue_cap.eia[1] = 1;
	ue->prop.msg_type.ar.ue_cap.eia[2] = 1;
	ue->prop.msg_type.ar.ue_cap.eia[3] = 1;
	ue->prop.msg_type.ar.ue_cap.eia[4] = 0;
	ue->prop.msg_type.ar.ue_cap.eia[5] = 0;
	ue->prop.msg_type.ar.ue_cap.eia[6] = 0;
	ue->prop.msg_type.ar.ue_cap.eia[7] = 0;
	//
	ue->prop.msg_type.ar.ue_cap.uea[0] = 1;
	ue->prop.msg_type.ar.ue_cap.uea[1] = 1;
	ue->prop.msg_type.ar.ue_cap.uea[2] = 0;
	ue->prop.msg_type.ar.ue_cap.uea[3] = 0;
	ue->prop.msg_type.ar.ue_cap.uea[4] = 0;
	ue->prop.msg_type.ar.ue_cap.uea[5] = 0;
	ue->prop.msg_type.ar.ue_cap.uea[6] = 0;
	ue->prop.msg_type.ar.ue_cap.uea[7] = 0;
	//
	ue->prop.msg_type.ar.ue_cap.uia[1] = 1;
	ue->prop.msg_type.ar.ue_cap.uia[2] = 0;
	ue->prop.msg_type.ar.ue_cap.uia[3] = 0;
	ue->prop.msg_type.ar.ue_cap.uia[4] = 0;
	ue->prop.msg_type.ar.ue_cap.uia[5] = 0;
	ue->prop.msg_type.ar.ue_cap.uia[6] = 0;
	ue->prop.msg_type.ar.ue_cap.uia[7] = 0;
	// 
	ue->prop.msg_type.ar.ms_net_cap.gea[1] = 1;
	ue->prop.msg_type.ar.ms_net_cap.gea[2] = 1;
	ue->prop.msg_type.ar.ms_net_cap.gea[3] = 1;
	ue->prop.msg_type.ar.ms_net_cap.gea[4] = 0;
	ue->prop.msg_type.ar.ms_net_cap.gea[5] = 0;
	ue->prop.msg_type.ar.ms_net_cap.gea[6] = 0;
	ue->prop.msg_type.ar.ms_net_cap.gea[7] = 0;
	// 
	RETURN 0;
}

int s1ap::delete_ue_ctx_t(uint32_t mme_ue_s1ap_id)
{
	LINE_TRACE();
	ue_ctx_t* ue = find_ue_by_mme_ue_s1ap_id(mme_ue_s1ap_id);
	if (!ue)	{RETURN -1;}
	for (int cur=0; cur<UE_LIST_SIZE; cur++)
	{
		if (ue_list[cur]==ue) 
		{
			delete ue_list[cur];
			ue_list[cur] = NULL;
			TestMsg_TRACE("\033[1;31mdelete ue_list[%d]=0x%x\033[0m\n", cur, ue_list[cur]);
			break;
		}
	}
	RETURN 0;
}
int s1ap::show_ue_ctx_t()
{
	LINE_TRACE();
	//TODO: new ue

	int cur;
	for (cur=0; cur<UE_LIST_SIZE; cur++)
	{
		if (ue_list[cur]) 
		{
			TestMsg_TRACE("show_ue_ctx_t, ue_List_num=%d, ue_list[%d]=0x%x, ue_list->imsi=%s, ue_list->MME_UE_ID=0x%08x\n", 
				ue_List_num,
				cur, ue_list[cur], 
				GetBinaryToHexStr(ue_list[cur]->prop.msg_type.ar.eps_mobile_id.imsi, sizeof(NAS_EPS_MOBILE_ID_STRUCT::imsi)),
				ue_list[cur]->MME_UE_ID
			); 
		}
	}
	RETURN 0;
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
	LINE_TRACE();
	int cur;
	for (cur=0; cur<UE_LIST_SIZE; cur++)
	{
		if (ue_list[cur])	
		{ 
			TestMsg_TRACE("find_ue_by_mme_ue_s1ap_id, ue_list[%d]=0x%x, ue_list->imsi=%s, ue_list->MME_UE_ID=0x%08x <--> mme_ue_s1ap_id=0x%08x\n", 
			cur, ue_list[cur], 
			GetBinaryToHexStr(ue_list[cur]->prop.msg_type.ar.eps_mobile_id.imsi, sizeof(NAS_EPS_MOBILE_ID_STRUCT::imsi)),
			ue_list[cur]->MME_UE_ID, 
			mme_ue_s1ap_id); 
			if (ue_list[cur]->MME_UE_ID==mme_ue_s1ap_id)	break;
		}
	}
	if (cur >= UE_LIST_SIZE)	{ RETURN NULL; }
	RETURN ue_list[cur];
}
ue_ctx_t* s1ap::find_ue_by_imsi(uint8_t *imsi){
	LINE_TRACE();
	int cur;
	NAS_EPS_MOBILE_ID_STRUCT	*id;
	char szmobile_type[20];
	for (cur=0; cur<UE_LIST_SIZE; cur++)
	{
		if (ue_list[cur])
		{	
			// temp_ue->prop.msg_type.ar.eps_mobile_id
			id = &ue_list[cur]->prop.msg_type.ar.eps_mobile_id;
			if (id->type==1)	strcpy(szmobile_type, "IMSI");
			else if (id->type==2)	strcpy(szmobile_type, "IMＥＩ");
			else if (id->type==3)	strcpy(szmobile_type, "IMEISV");
			else if (id->type==4)	strcpy(szmobile_type, "TMSI/P-TMSI/M-TMSI");
			else if (id->type==5)	strcpy(szmobile_type, "TMGI and optional MB");
			else if (id->type==0)	strcpy(szmobile_type, "No Identity (note 1) ");

			TestMsg_TRACE("find_ue_by_imsi, ue_list[%d]=0x%x, MME_UE_ID=0x%08x, mobile_type=%d, id->imsi=%s, imsi=%s, %d @ %s\n", 
				cur, ue_list[cur], 
				ue_list[cur]->MME_UE_ID,
				id->type, 
				GetBinaryToHexStr(id->imsi, sizeof(id->imsi)),
				GetBinaryToHexStr(imsi, sizeof(id->imsi)),
				__LINE__, __FILE__
			); 

			if (id->type==1)
			{
				if (!memcmp(id->imsi, imsi, sizeof(id->imsi)))	break;
			}
		}
	}
	if (cur >= UE_LIST_SIZE)	{RETURN NULL;}
	RETURN ue_list[cur];
}
int s1ap::get_next_mme_ue_id(){
	RETURN m_mme_ue_s1ap_id++;
}
int s1ap::get_next_ctrl_fteid(){
	RETURN m_mme_global_ctrl_fteid+=0x01000000;
	// return m_mme_global_ctrl_fteid++;
	//return m_mme_global_ctrl_fteid;
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
	return m_ue_ipv4+=htonl(1);
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
	m_mme_ue_s1ap_id = 3410577100;
	m_ue_ipv4 = inet_addr(PDN_IPv4_BEGIN);
	m_spgw_addr_ipv4=inet_addr(SGW_IP);
	m_spgw = spgw::get_instance();
	//m_spgw->init();	// The init() function is already put in get_instance() function
	m_s1ap_decode = s1ap_decode::get_instance();
	m_s1ap_decode->init();
	m_s1ap_encode = s1ap_encode::get_instance();
	m_s1ap_encode->init();
	s1ap_args = new s1ap_args_t();
	
	m_mme_global_ctrl_fteid = 0x00000000;
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
		printf("Receive Message Type: S1Setup\n");
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
		RETURN m_s1ap_encode->encode_S1Response_message(sendbuf,s1ap_args);
	}

	// Initial UE Message
	else if(buf[0]==0x0c){
		if(buf[1]!=0x40){printf("#error: InitialUEMessage with wrong criticalty\n"); exit(1);}
		LINE_TRACE();
		//ue_ctx_t temp_ue;
		uint32_t enb_ue_id,mme_ue_id;
		ue_ctx_t temp_ue;
		ue_ctx_t *ue = NULL;
		m_s1ap_decode->decode_s1ap_InitialUEMessage_message(buf+2, &temp_ue, &temp_ue.eNB_UE_ID);
		if (!(ue=find_ue_by_mme_ue_s1ap_id(temp_ue.MME_UE_ID)))
		{
			ue = add_new_ue_ctx_t();
			if (!ue)	{ printf("add_new_ue_ctx_t() failed, ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1; }
			else 	printf("get new ue=0x%x\n", ue);
			memcpy(ue, &temp_ue, sizeof(ue_ctx_t));
			set_inital_ue_ctx_t(ue);
		}
		printf("ue->sec.k_enb:%x %x %x\n",ue->sec.k_enb[0],ue->sec.k_enb[1],ue->sec.k_enb[2]);
		//m_s1ap_decode->decode_s1ap_InitialUEMessage_message(buf+2,&temp_ue,&temp_ue.eNB_UE_ID);
		//memcpy(ue,&temp_ue,sizeof(ue_ctx_t));

		TestMsg_TRACE("ue=0x%x, ue->MME_UE_ID=0x%x\n", ue, ue->MME_UE_ID);
		
		// ue->MME_UE_ID = m_mme_ue_s1ap_id;	//return current mme_ue_s1ap_id
		//ue->init();
//Delete this after debugging
//ue->MME_UE_ID=get_next_mme_ue_id(); ue->eNB_UE_ID=1;
//TODO: not give ue_list but give right ue to encode initialUEMessage
printf("ue eps_mobile_id_type: %02x\n",ue->prop.msg_type.ar.eps_mobile_id.type);

		//attach request
		if(ue->prop.request_type==0x41){
			LINE_TRACE();
			printf("Receive Message Type: Attach Request\n");
			// GUTI
			//TODO: not just send Identity Request but find all ue with guti
			//ue->MME_UE_ID = get_next_mme_ue_id();
			if(ue->prop.msg_type.ar.eps_mobile_id.type == 6){	
				RETURN m_s1ap_encode->encode_Identity_Request_message(sendbuf,&ue->MME_UE_ID,&ue->eNB_UE_ID);
			}

			// IMSI
			else if(ue->prop.msg_type.ar.eps_mobile_id.type==1){
				{RETURN m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);}
			}
			else
				{RETURN m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);}
		}
		//service request (Reserved 0)
		else if(ue->prop.request_type==0)
		{
			LINE_TRACE();
			printf("Receive Message Type: Service Request\n");
			ue->prop.msg_type.sr.Service_Request_Flag=1;
			RETURN m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);
			
			
			// uint32_t s11_sgw_fteid,s1u_sgw_fteid;
			
			// printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\ncreate Asession request\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
			// int next_ctrl_fteid = get_next_ctrl_fteid(); //the other fteid
			// m_spgw->manage_create_session_request(next_ctrl_fteid,5,9,&s11_sgw_fteid,&s1u_sgw_fteid);
			// ue->erab[5].s11_sgw_fteid = s11_sgw_fteid;
			// ue->erab[5].s11_mme_fteid = next_ctrl_fteid;
			// ue->erab[5].s1u_sgw_fteid = s1u_sgw_fteid;
			// ue->erab[5].pdn_ipv4 = get_next_pdn_ipv4();
			// ue->erab[5].pdn_ipv4 = m_ue_ipv4-1;
			// ue->erab[5].s1u_ipv4 = get_spgw_addr_ipv4();
			
			// //get_next_guti(&ue->prop.msg_type.ar.eps_mobile_id.guti);
			
			// RETURN m_s1ap_encode->encode_InitialContextSetupRequest_UECapabilityInformation_message(sendbuf,ue);
		}
		else if(ue->prop.request_type==0x48)
		{
			LINE_TRACE();
			printf("Receive Message Type: Tracking Area Update Request\n");
			RETURN m_s1ap_encode->encode_Tracking_Area_Update_Accept(sendbuf, ue);
		}
		RETURN -1;
	}

	//Uplink NAS Transport
	else if(buf[0]==0x0d){
		LINE_TRACE();
		
		if(buf[1]!=0x40){printf("#error: UplinkNASTransport with wrong criticalty\n");}
		uint32_t mme_ue_s1ap_id = 0;
		ue_ctx_t temp_ue;
		UPLINK_NAS_TRANSPORT_STRUCT nas;
				
		m_s1ap_decode->decode_s1ap_UplinkNASTransport_message(buf+2,&temp_ue,&mme_ue_s1ap_id,&nas);
		ue_ctx_t* ue = find_ue_by_mme_ue_s1ap_id(mme_ue_s1ap_id);
		if (!ue)	{ printf("\033[1;31mfind_ue_by_mme_ue_s1ap_id failed\033[0m], ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1;}
		LINE_TRACE();
		TestMsg_TRACE("request_type=0x%x, ue=0x%x, mme_ue_s1ap_id=0x%08x, mobile_type=%d, imsi=%s\n", nas.request_type, ue, mme_ue_s1ap_id, nas.prop.id.type, GetBinaryToHexStr(nas.prop.id.imsi,sizeof(nas.prop.id.imsi)));

		// identity response
		if(nas.request_type==0x56){
			LINE_TRACE();
			printf("Receive Message Type: Identity Response\n");
//Delete this after debugging
//ue=new ue_ctx_t(); ue->MME_UE_ID=get_next_mme_ue_id(); ue->eNB_UE_ID=1;
			memcpy(&ue->prop.msg_type.ar.eps_mobile_id,&nas.prop.id,sizeof(ue->prop.msg_type.ar.eps_mobile_id));
			RETURN m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);
		}
		// Authentication failure
		if(nas.request_type==0x5c){
			LINE_TRACE();
			printf("Receive Message Type: Authentication Failure\n");
			// Synch failure
			if(nas.prop.af.emm_cause==21){
				resync(nas.prop.af.sqn_ms_xor_ak,ue->sec.rand,ue->sec.sqn);
				RETURN m_s1ap_encode->encode_Authentication_Request_message(sendbuf,ue);
			}
		}
		// Authentication Response
		if(nas.request_type==0x53){
			int i;
			for(i=0;i<8;i++) if(ue->sec.res[i]!=nas.prop.res.res[i]) printf("security: ue res error\n");
			//TODO: res error
			//TODO: choose EIA EEA here
			ue->sec.dl_count = 0;
			ue->sec.ul_count = 0;
			ue->sec.int_al = 1;
			ue->sec.enc_al = 0;
			init_k_int_enc(ue->sec.k_asme,ue->sec.k_nasint,ue->sec.k_nasenc,1,0);
			RETURN m_s1ap_encode->encode_Security_Mode_Command_message(sendbuf,ue);
		}
		//Security Mode Complete
		//TODO: all *if* after Security Mode Complete should check int and enc
		if(nas.request_type==0x5e){
			printf("Receive Message Type: Security Mode Complete\n");
			printf("dl_count: %d\n",ue->sec.dl_count);
			if(ue->prop.msg_type.sr.Service_Request_Flag==1){
				
				uint32_t s11_sgw_fteid,s1u_sgw_fteid;
				printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\ncreate Asession request\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
				int next_ctrl_fteid = get_next_ctrl_fteid(); //the other fteid
				m_spgw->manage_create_session_request(next_ctrl_fteid,5,9,&s11_sgw_fteid,&s1u_sgw_fteid);
				ue->erab[5].s11_sgw_fteid = s11_sgw_fteid;
				ue->erab[5].s11_mme_fteid = next_ctrl_fteid;
				ue->erab[5].s1u_sgw_fteid = s1u_sgw_fteid;
				ue->erab[5].pdn_ipv4 = get_next_pdn_ipv4();
				ue->erab[5].s1u_ipv4 = get_spgw_addr_ipv4();
				get_next_guti(&ue->prop.msg_type.ar.eps_mobile_id.guti);
				
				RETURN m_s1ap_encode->encode_InitialContextSetupRequest_UECapabilityInformation_message(sendbuf,ue);
			}
			else if(ue->prop.msg_type.sr.Service_Request_Flag==0)
			{
				RETURN m_s1ap_encode->encode_ESM_Information_Request_message(sendbuf,ue);
			}
		}
		//ESM Mode response
		if(nas.request_type==0xda){
			printf("Receive Message Type: ESM Information Response\n");
			if(nas.prop.esm_info.len>40) printf("ESM Mode response error: apn name len>40\n");
			memcpy(ue->prop.msg_type.ar.apn_name,nas.prop.esm_info.apn_name,nas.prop.esm_info.len);
			ue->prop.msg_type.ar.apn_len = nas.prop.esm_info.len;
			next_message->type = 9;
			next_message->temp_ue = ue;
			RETURN m_s1ap_encode->encode_EMM_Information_Request_message(sendbuf,ue);
		}
		//Tracking Area Update Request
		if(nas.request_type==0x48){
			printf("Receive Message Type: Tracking Area Update Request\n");
			RETURN m_s1ap_encode->encode_Tracking_Area_Update_Accept(sendbuf, ue);
		}
		//PDN connectivity request
		if(nas.request_type==0xd0){
			printf("Receive Message Type: PDN Connectivity Request\n");
			printf("HHHHHHHHHHHHHHHHHH");
			
			uint32_t s11_sgw_fteid,s1u_sgw_fteid;
			int next_ctrl_fteid = get_next_ctrl_fteid();
			printf("AAAAAAAAAAAAAAAAAAAAAA\ncreate session request\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
			
			m_spgw->manage_create_session_request(next_ctrl_fteid,6,5,&s11_sgw_fteid,&s1u_sgw_fteid);
			ue->erab[6].s11_sgw_fteid = s11_sgw_fteid;
			ue->erab[6].s11_mme_fteid = next_ctrl_fteid;
			ue->erab[6].s1u_sgw_fteid = s1u_sgw_fteid;
			ue->erab[6].pdn_ipv4 = get_next_pdn_ipv4();
			// ue->erab[6].pdn_ipv4 = m_ue_ipv4-1;
			ue->erab[6].s1u_ipv4 = get_spgw_addr_ipv4();
			ue->erab[6].ims_ipv4 = inet_addr(P_CSCF_IP);
			
			//測試用
			next_message->type = 8;
			next_message->temp_ue = ue;
			
			RETURN m_s1ap_encode->encode_PDN_connectivity_response(sendbuf,ue);
		}
		
		// //Extended Service reject
		// if(nas.request_type==0x4c){
		// 	LINE_TRACE();
		// 	printf("Get Extended service request\n");
		// 	if (nas.prop.esm_info.len <= sizeof(ue->prop.msg_type.ar.apn_name))
		// 		memcpy(ue->prop.msg_type.ar.apn_name, nas.prop.esm_info.apn_name, nas.prop.esm_info.len);
		// 	else
		// 		TestMsg_TRACE("nas.prop.esm_info.len(%d) > %s\n", nas.prop.esm_info.len, sizeof(ue->prop.msg_type.ar.apn_name));
		// 	TestMsg_TRACE("ue->prop.msg_type.ar.apn_name=0x%x, %s\n", ue->prop.msg_type.ar.apn_name, nas.prop.esm_info.apn_name);
		// 	LINE_TRACE();
		// 	ue->prop.msg_type.ar.apn_len = nas.prop.esm_info.len;
		// 	LINE_TRACE();
		// 	//next_message->type = 8;
		// 	//next_message->temp_ue = ue;
		// 	RETURN m_s1ap_encode->encode_service_reject(sendbuf, ue);
		// }
			
	}
	
	//UEContextReleaseRequest
	else if(buf[0]==0x12){
		LINE_TRACE();
		if(buf[1]!=0x40){printf("#error: UEContextReleaseRequest with wrong criticalty\n");}
		printf("Receive Message Type: UE Context Release Request\n");
		//m_s1ap_decode->decode_s1ap_UEContextReleaseRequest_message(buf+2,&temp_ue);
		ue_ctx_t temp_ue;
		ue_ctx_t *ue = NULL;
		m_s1ap_decode->decode_s1ap_UEContextReleaseRequest_message(buf+2,&temp_ue);
		
		if (!(ue=find_ue_by_mme_ue_s1ap_id(temp_ue.MME_UE_ID)))
		{ printf("\033[1;31mfind_ue_by_mme_ue_s1ap_id failed\033[0m], ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1;}
		// {
		// 	ue = add_new_ue_ctx_t();
		// 	if (!ue)	{ printf("add_new_ue_ctx_t() failed, ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1; }
		// 	else 	printf("get new ue=0x%x\n", ue);
		// 	memcpy(ue, &temp_ue, sizeof(ue_ctx_t));
		// }
		


		
		//memcpy(ue,&temp_ue,sizeof(ue_ctx_t));
		
		//Fixme: find session by UE but not constant
		//m_spgw->manage_end_session_request(m_mme_global_ctrl_fteid);

		int ret = m_s1ap_encode->encode_UEContextReleaseCommand_message(sendbuf,ue);
		if (delete_ue_ctx_t(temp_ue.MME_UE_ID)<0)	{ printf("\033[1;31mdelete_ue_ctx_t failed\033[0m], %d @ %s\n", __LINE__, __FILE__); RETURN -1;}
		RETURN ret;
	}

	
	RETURN -1;
}
int s1ap::decode_s1ap_successfulOutcome_message(char* eNB_IP,uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT* next_message){
	
	
	//InitialContextSetupResponse
	if(buf[0]==0x09){
		LINE_TRACE();
		printf("Receive Message Type: Initial Context Setup Response\n");
		//FIXME: extract mme_ue_s1ap_id and find by it
		ue_ctx_t	temp_ue;
		erab_setuplistctxtsures_t est;
		m_s1ap_decode->decode_s1ap_InitialContextSetup_message(buf+2, &temp_ue, &est);
		TestMsg_TRACE("ue->MME_UE_ID=0x%08x, ue->eNB_UE_ID=0x%08x\n", temp_ue.MME_UE_ID, temp_ue.eNB_UE_ID);
		ue_ctx_t* ue = find_ue_by_mme_ue_s1ap_id(temp_ue.MME_UE_ID);
		if (!ue)	{ printf("\033[1;31mfind_ue_by_mme_ue_s1ap_id failed\033[0m], ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1;}
		TestMsg_TRACE("ue->MME_UE_ID=0x%08x, ue->eNB_UE_ID=0x%08x\n", temp_ue.MME_UE_ID, temp_ue.eNB_UE_ID);
		m_spgw->manage_modify_bearer_request(ue->erab[5].s11_sgw_fteid,est);

		if(ue->prop.msg_type.sr.Service_Request_Flag==1)
		{
			ue->prop.msg_type.sr.Service_Request_Flag=0;
		}
		
		int index = find_eNB_by_IP(eNB_IP);
		eNB_LIST[index].UE_LIST[eNB_LIST[index].UE_NUM]=temp_ue.MME_UE_ID;
		eNB_LIST[index].UE_NUM++;
		eNB_LIST[index].print_properties();
		LINE_TRACE();
		
	}
	//E-RABSetupResponse QCI:5 & QCI:1
	if(buf[0]==0x05){
		LINE_TRACE();
		printf("Receive Message Type: E-RABSetupResponse\n");
		ue_ctx_t	temp_ue;
		int ebid;
		erab_setuplistctxtsures_t est;
		m_s1ap_decode->decode_s1ap_ERABSetupResponse_message(buf+2, &temp_ue, &est);
		TestMsg_TRACE("ue->MME_UE_ID=0x%08x, ue->eNB_UE_ID=0x%08x\n", temp_ue.MME_UE_ID, temp_ue.eNB_UE_ID);
		ue_ctx_t* ue = find_ue_by_mme_ue_s1ap_id(temp_ue.MME_UE_ID);
		if (!ue)	{ printf("\033[1;31mfind_ue_by_mme_ue_s1ap_id failed\033[0m], ret=0x%x, %d @ %s\n", ue, __LINE__, __FILE__); RETURN -1;}
		TestMsg_TRACE("ue->MME_UE_ID=0x%08x, ue->eNB_UE_ID=0x%08x\n", temp_ue.MME_UE_ID, temp_ue.eNB_UE_ID);
		LINE_TRACE();
		ebid = est.ebi;
		LINE_TRACE();
		m_spgw->manage_modify_bearer_request(ue->erab[ebid].s11_sgw_fteid,est);
		LINE_TRACE();
	}

		

	
	
	
	RETURN -1;
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
		
		//E-RABSetupRequest
		if(next_message->type == 8){
			next_message->type = -1;

			// Create Session Request, you can receive some information here
			uint32_t s11_sgw_fteid,s1u_sgw_fteid;
			printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\ncreate QCI 1 session request\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

			m_spgw->manage_create_session_request(get_next_ctrl_fteid(),7,1,&s11_sgw_fteid,&s1u_sgw_fteid);
			
			next_message->temp_ue->erab[7].s11_sgw_fteid = s11_sgw_fteid;
			next_message->temp_ue->erab[7].s11_mme_fteid = get_next_ctrl_fteid();
			next_message->temp_ue->erab[7].s1u_sgw_fteid = s1u_sgw_fteid;
			next_message->temp_ue->erab[7].pdn_ipv4 = get_next_pdn_ipv4();
			next_message->temp_ue->erab[7].s1u_ipv4 = get_spgw_addr_ipv4();
			
			return 0;

			uint8_t		caller_imsi[15], casllee_imsi[15];
			uint32_t	caller_ip = next_message->temp_ue->erab[7].pdn_ipv4;
			uint32_t 	callee_ip = inet_addr(P_CSCF_IP);
			uint16_t	caller_port = htons(40006), callee_port = htons(40000);
			
			for (int i=0; i<next_message->temp_ue->erab_tft.filter_num; i++)
			{
				
				next_message->temp_ue->erab_tft.filter[i].remote_ip = ((i%2)==0)? callee_ip:caller_ip;
				next_message->temp_ue->erab_tft.filter[i].remote_ip_mask = 0xffffffff;
				next_message->temp_ue->erab_tft.filter[i].LPort = (((i%2)==1)? callee_port:caller_port) + ((i>1)? 0x0100:0);
				next_message->temp_ue->erab_tft.filter[i].RPort = (((i%2)==0)? callee_port:caller_port) + ((i>1)? 0x0100:0);
				TestMsg_TRACE("i=%d, (i%2)=%d, LPort=%d, RPort=%d\n", i, (i%2), ntohs(next_message->temp_ue->erab_tft.filter[i].LPort), ntohs(next_message->temp_ue->erab_tft.filter[i].RPort));
			}

			return m_s1ap_encode->encode_ERABSetRequest_message(sendbuf,next_message->temp_ue,7);
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

int s1ap::encode_ERABSetRequest_qci1(uint8_t *sendbuf, traffic_flow_template_t *tft)
{
	LINE_TRACE();
	if (!sendbuf)	return -1;

	ue_ctx_t* temp_ue = find_ue_by_imsi(tft->imsi);
	if (!temp_ue)	{ printf("\033[1;31mfind_ue_by_imsi failed\033[0m], ret=0x%x, %d @ %s\n", temp_ue, __LINE__, __FILE__); RETURN -1;}
	
	show_ue_ctx_t();
	
	memcpy(&temp_ue->erab_tft, tft, sizeof(temp_ue->erab_tft));
	
	
	RETURN m_s1ap_encode->encode_ERABSetRequest_message(sendbuf, temp_ue, 7);
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
