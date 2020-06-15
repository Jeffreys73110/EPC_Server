#ifndef __S1AP_H__
#define __S1AP_H__
#include "s1ap_common.h"
#include "spgw.h"
#include "s1ap_decode.h"
#include "s1ap_encode.h"
#include <pthread.h>
class s1ap{
private:
	static s1ap* m_instance;
	spgw* m_spgw;
	s1ap_decode* m_s1ap_decode;
	s1ap_encode* m_s1ap_encode;
	enb_ctx_t* enb_list;
	int eNB_NUM;
	enb_ctx_t eNB_LIST[10];
	ue_ctx_t* ue_list;
	s1ap_args_t* s1ap_args;
	NAS_EPS_MOBILE_ID_GUTI_STRUCT m_next_guti;
	uint32_t m_ue_ipv4;
	uint32_t m_spgw_addr_ipv4;
	uint32_t m_mme_ue_s1ap_id;
	uint32_t m_mme_global_ctrl_fteid;
public:
	s1ap();
	static s1ap* get_instance();
	void init();
	
	int find_eNB_by_IP(char* IP);
	//enb_ctx_t* add_new_enb_ctx_t();
	ue_ctx_t* add_new_ue_ctx_t();
	ue_ctx_t* find_ue_by_mme_ue_s1ap_id(uint32_t);

	/* handle enb->mme pdu */
	int handle_s1ap_pdu(char* eNB_IP,uint8_t* buf,uint8_t* sendbuf,NEXT_MESSAGE_STRUCT*);

	/* decode message */
	int decode_s1ap_initiating_message(char* eNB_IP,uint8_t* buf,uint8_t*,NEXT_MESSAGE_STRUCT*);
	int decode_s1ap_successfulOutcome_message(char* eNB_IP,uint8_t*,uint8_t*,NEXT_MESSAGE_STRUCT*);
	int decode_s1ap_UnsuccessfulOutcome_message(uint8_t*,uint8_t*,NEXT_MESSAGE_STRUCT*);
	/* get functions */
	int get_next_mme_ue_id();
	int get_next_ctrl_fteid();
	uint32_t get_next_ue_ipv4();
	uint32_t get_next_pdn_ipv4();
	uint32_t get_spgw_addr_ipv4();
	void get_next_guti(NAS_EPS_MOBILE_ID_GUTI_STRUCT*);
};
#endif
