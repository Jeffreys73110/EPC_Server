#ifndef __NAS_ENCODE_H__
#define __NAS_ENCODE_H__
#include<stdint.h>
#include"s1ap_common.h"
#include"nas_common.h"

class nas_encode{
private:
	static nas_encode* m_instance;
public:
	nas_encode();
	static nas_encode* get_instance();
	int encode_Identity_Request_message_IMSI(uint8_t*);
	int encode_Authentication_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_Security_Mode_Command(uint8_t* buf,ue_ctx_t* ue);
	int encode_UE_security_capability(uint8_t* buf,ue_ctx_t* ue);
	int encode_GPRS_Timer(uint8_t* buf);
	int encode_Tracking_area_identity_list(uint8_t* buf);
	int encode_EPS_bearer_context_status(uint8_t* buf);
	int encode_EPS_network_feature_support(uint8_t* buf);
	int encode_ESM_Information_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_Tracking_Area_Update_Accept(uint8_t* buf,ue_ctx_t* ue);
	int encode_Service_reject(uint8_t* buf,ue_ctx_t* ue);
	int encode_EMM_Information_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_Activate_default_context_request(uint8_t* buf,ue_ctx_t* ue);
	int encode_Activate_default_EPS_bearer_context_req(uint8_t* buf,ue_ctx_t* ue);
	int encode_Activate_default_EPS_bearer_context_req_qci1(uint8_t* buf,ue_ctx_t* ue);
	int encode_EPS_ID_GUTI(uint8_t* buf,ue_ctx_t* ue);
	int encode_Attach_Accept(uint8_t* buf,ue_ctx_t* ue);
	
};
#endif
