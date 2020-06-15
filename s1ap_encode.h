#ifndef __S1AP_ENCODE_H_INCLUDED__
#define __S1AP_ENCODE_H_INCLUDED__
#include<stdint.h>
#include"nas_encode.h"
class s1ap_encode{
private:
	nas_encode* m_nas_encode;
	static s1ap_encode* m_instance;
	int encode_MMEname(uint8_t*,s1ap_args_t*);
	int encode_pLMN(uint8_t*,s1ap_args_t*);
	int encode_ServedGroupID(uint8_t*,s1ap_args_t*);
	int encode_ServedMMECs(uint8_t*,s1ap_args_t*);
	int encode_ServedGUMMEIs(uint8_t*,s1ap_args_t*);
	int encode_RelativeMMECapacity(uint8_t*,s1ap_args_t*);
	int encode_initiate_message(uint8_t*,s1ap_args_t*);
	int encode_MME_UE_S1AP_ID(uint8_t*,uint32_t);
	int encode_ENB_UE_S1AP_ID(uint8_t*,uint32_t);
	int encode_NAS_PDU_Identity_Request_IMSI(uint8_t*);
	int encode_NAS_PDU_ESM_Information_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_NAS_PDU_Tracking_Area_Update_Accept(uint8_t* buf,ue_ctx_t* ue);
	int encode_NAS_PDU_EMM_Information_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_NAS_PDU_Service_reject(uint8_t* buf,ue_ctx_t* ue);
	int encode_UESecurityCapabilities(uint8_t* buf,ue_ctx_t* ue);
	int encode_ERABToSetupListCtxtSUReq(uint8_t* buf,ue_ctx_t* ue,int ebi,int msg_type);
	int encode_ERABToBeSetupListBearerSUReq(uint8_t* buf,ue_ctx_t* ue);
	int encode_ERABToBeSetupListBearerSUReq_qci1(uint8_t* buf,ue_ctx_t* ue);
	int encode_SecurityKey(uint8_t* buf,ue_ctx_t* ue);
	int encode_UERadioCapability(uint8_t* buf,ue_ctx_t* ue);
	int encode_SRVCCOperationPossible(uint8_t* buf);
	int encode_UE_S1AP_IDs(uint8_t*,ue_ctx_t*);
	int encode_Cause(uint8_t*);
public:
	s1ap_encode();
	void init();
	static s1ap_encode* get_instance();
	int encode_S1Response_message(uint8_t*,s1ap_args_t*);
	int encode_Identity_Request_message(uint8_t*,uint32_t*,uint32_t*);
	int encode_NAS_PDU_Authentication_Request(uint8_t* buf,ue_ctx_t* ue);
	int encode_Authentication_Request_message(uint8_t* buf,ue_ctx_t* ue);
	int encode_NAS_PDU_Security_Mode_Command(uint8_t*,ue_ctx_t*);
	int encode_Security_Mode_Command_message(uint8_t*,ue_ctx_t*);
	int encode_ESM_Information_Request_message(uint8_t*,ue_ctx_t*);
	int encode_Tracking_Area_Update_Accept(uint8_t*,ue_ctx_t*);
    int encode_EMM_Information_Request_message(uint8_t*,ue_ctx_t*);
	int encode_InitialContextSetupRequest_message(uint8_t* buf,ue_ctx_t* ue,int ebi);
	int encode_ERABSetRequest_message(uint8_t* buf,ue_ctx_t* ue,int ebi);
	int encode_InitialContextSetupRequest_UECapabilityInformation_message(uint8_t*,ue_ctx_t*);
	int encode_UEContextReleaseCommand_message(uint8_t*,ue_ctx_t*);
	int encode_PDN_connectivity_response(uint8_t* ,ue_ctx_t*);
	int encode_service_reject(uint8_t* ,ue_ctx_t*);
};
#endif
