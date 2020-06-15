#ifndef __NAS_DECODE_H__
#define __NAS_DECODE_H__
#include<stdint.h>
#include"nas_common.h"

class nas_decode{
private:
	static nas_decode* m_instance;
public:
	nas_decode();
	static nas_decode* get_instance();

	void init();
	int decode_message_type_pos(uint8_t*,int*,int*);
	void decode_eps_attach_type(uint8_t*,int,uint8_t*);
	void decode_nas_key_set_id(uint8_t*,int,NAS_NAS_KEY_SET_ID_STRUCT*);
	void decode_eps_mobile_id(uint8_t*,NAS_EPS_MOBILE_ID_STRUCT*,int*);
	void decode_ue_network_capability(uint8_t*,NAS_UE_NETWORK_CAPABILITY_STRUCT*,int*);
	void decode_esm_information_transfer_flag(uint8_t*,bool*,int*);
	void decode_protocol_configuration_options(uint8_t*,NAS_PROTOCOL_CONFIGURATION_STRUCT*,int*);
	void decode_pdn_connectivity_request(uint8_t*,NAS_PDN_CONNECTIVITY_REQUEST_STRUCT*,int*);
	void decode_last_visited_registered_tai(uint8_t*,NAS_TRACKING_AREA_ID_STRUCT*,int*);
	void decode_drx_parameter(uint8_t*,NAS_DRX_PARAMETER_STRUCT*,int*);
	void decode_ms_network_capability(uint8_t*,NAS_MS_NETWORK_CAPABILITY_VALUE_STRUCT*,int*);
	void decode_tmsi_status(uint8_t*,int,bool*);
	void decode_mobile_station_classmark2(uint8_t*,NAS_MS_CLASSMARK2_STRUCT*,int*);
	void decode_voice_domain_pref_and_ue_usage_setting_value(uint8_t*,NAS_VOICE_DOMAIN_PREF_AND_UE_USAGE_SETTING_VALUE_STRUCT*,int*);
	void decode_Authentication_failure_Parameter(uint8_t*, UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT*);
	void decode_guti_type(uint8_t*,int,bool*);
	void decode_EMM_cause(uint8_t* msg,int* emm_cause);
	void decode_Authentication_failure(uint8_t* msg,UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT* emm_cause);
	void decode_attach_request(uint8_t*,NAS_ATTACH_REQUEST_STRUCT*);
	void decode_identity_response(uint8_t* msg,NAS_EPS_MOBILE_ID_STRUCT* eps_mobile_id);
	void decode_Authentication_response(uint8_t* msg,UPLINK_NAS_TRANSPORT_AUTHENTICATION_RESPONSE_STRUCT* nas);
	void decode_InitialUEMessage_nas_pdu(uint8_t*,NAS_INITIAL_UE_MESSAGE_STRUCT*);
	void decode_UplinkNASTransportMessage_nas_pdu(uint8_t*,UPLINK_NAS_TRANSPORT_STRUCT*);
	void decode_ESM_information_response(uint8_t* msg,UPLINK_NAS_TRANSPORT_ESM_INFORMATION_RESPONSE_STRUCT* nas);
	void decode_service_request(uint8_t*,NAS_SERVICE_REQUEST_STRUCT*);
};
#endif
