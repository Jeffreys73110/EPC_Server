#ifndef __S1AP_DECODE_H_INCLUDED__
#define __S1AP_DECODE_H_INCLUDED__

#include"s1ap_common.h"
#include"nas_decode.h"

class s1ap_decode{
private:
	nas_decode* m_nas_decode;
	static s1ap_decode* m_instance;
public:
	s1ap_decode();
	static s1ap_decode* get_instance();

	void init();
	void decode_pLMN(uint8_t*, char*, enb_ctx_t*, bool);
	void decode_homeENB_ID(uint8_t*, enb_ctx_t*);
	void decode_macroENB_ID(uint8_t*, enb_ctx_t*);
	void decode_ProtocolIE_Global_ENB_ID(uint8_t*,enb_ctx_t*);
	void decode_ProtocolIE_eNBname(uint8_t*,enb_ctx_t*);
	void decode_ProtocolIE_SupportedTAs(uint8_t*,enb_ctx_t*);
	void decode_ProtocolIE_DefaultPagingDRX(uint8_t*,enb_ctx_t*);
	void decode_ProtocolIE_eNB_UE_S1AP_ID(uint8_t*,uint32_t*);
	void decode_ProtocolIE_MME_UE_S1AP_ID(uint8_t*,uint32_t*);
	void decode_ProtocolIE_TAI(uint8_t*,enb_ctx_t*);
	void decode_ProtocolIE_ERAB_SetupListCtxtSURes(uint8_t*,erab_setuplistctxtsures_t*);
	void decode_InitialUEMessage_ProtocolIE_NAS(uint8_t*,ue_ctx_t*);
	void decode_UplinkNASTransportMessage_ProtocolIE_NAS(uint8_t*,UPLINK_NAS_TRANSPORT_STRUCT*);
	int decode_S1Setup_ProtocolIE_Field(uint8_t*,enb_ctx_t*);
	int decode_UplinkNASTransport_ProtocolIE_Field(uint8_t* buf,ue_ctx_t* ue,uint32_t* mme_ue_id,UPLINK_NAS_TRANSPORT_STRUCT*);
	int decode_InitialUEMessage_ProtocolIE_Field(uint8_t*,ue_ctx_t*,uint32_t*);
	int decode_s1ap_UplinkNASTransport_ProtocolIE_Field(uint8_t*,ue_ctx_t*,uint32_t*,UPLINK_NAS_TRANSPORT_STRUCT*);
	int decode_InitialContextSetup_ProtocolIE_Field(uint8_t* buf,erab_setuplistctxtsures_t* est);
	int decode_UEContextReleaseRequest_ProtocolIE_Field(uint8_t*,ue_ctx_t*);

	void decode_s1ap_S1Setup_message(uint8_t*,enb_ctx_t* enb);
	void decode_s1ap_UplinkNASTransport_message(uint8_t*,ue_ctx_t*,uint32_t*,UPLINK_NAS_TRANSPORT_STRUCT*);
	void decode_s1ap_InitialUEMessage_message(uint8_t* buf, ue_ctx_t* enb,uint32_t*);
	void decode_s1ap_InitialContextSetup_message(uint8_t* buf,erab_setuplistctxtsures_t* est);
	void decode_s1ap_UEContextReleaseRequest_message(uint8_t*,ue_ctx_t*);
};

#endif
