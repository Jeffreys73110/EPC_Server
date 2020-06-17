#ifndef __NAS_COMMON_H__
#define __NAS_COMMON_H__
#include<stdint.h>

struct NAS_TRACKING_AREA_ID_STRUCT{
	uint16_t mcc;
	uint16_t mnc;
	uint16_t tac;
};
struct NAS_UE_NETWORK_CAPABILITY_STRUCT{
	bool eea[8];
	bool eia[8];
	bool uea_present;
	bool uea[8];
	bool uia_present;
	bool uia[8];
	bool ucs2;
//TODO: more info after uia
};
struct NAS_EPS_MOBILE_ID_GUTI_STRUCT{
	uint32_t m_tmsi;
	uint16_t mmegi;
	uint16_t mcc;
	uint16_t mnc;
	uint8_t mmec;
};
struct NAS_EPS_MOBILE_ID_STRUCT{
	NAS_EPS_MOBILE_ID_GUTI_STRUCT guti;
	uint8_t imsi[15];
	uint8_t imei[15];
	uint8_t type;
	
	/* Type of identity (octet 3) 
	3 2 1
	0 0 1 IMSI
	0 1 0 IMEI
	0 1 1 IMEISV
	1 0 0 TMSI/P-TMSI/M-TMSI
	1 0 1 TMGI and optional MB
	0 0 0 No Identity (note 1) 	*/
};
struct NAS_NAS_KEY_SET_ID_STRUCT{
	bool tsc;
	uint8_t nas_ksi;
};
struct NAS_DRX_PARAMETER_STRUCT{
	uint8_t split_pg_cycle_code;
	uint8_t drx_cycle_length_coeff_and_value;
	uint8_t non_drx_time;
	bool split_on_ccch;
};
struct NAS_MS_NETWORK_CAPABILITY_VALUE_STRUCT{
	uint8_t	ss_screen_indicator;
	bool gea[8];
	bool sm_via_ded;
	bool sm_via_gprs;
	bool ucs2;
	bool solsa;
	bool revision;
	bool pfc;
	bool lcsva;
	bool ho_g2u_iu;
	bool ho_g2e_s1;
	bool emm_com;
	bool isr;
	bool srvcc;
	bool epc;
	bool nf;
	bool geran;
};
struct NAS_MS_CLASSMARK2_STRUCT{
	uint8_t	revision;
	uint8_t	rf_power_cap;
	uint8_t	ss_screen_indicator;
	bool	esing;
	bool	a5_1;
	uint8_t len;
	uint8_t contents[80];					//248
	bool	ps_cap;
	bool	sm_cap;
	bool	vbs;
	bool	vgcs;
	bool	fc;
	bool	cm3;
	bool	lcsva;
	bool	ucs2;
	bool	solsa;
	bool	cmsp;
	bool	a5_2;
	bool	a5_3;
};
struct NAS_VOICE_DOMAIN_PREF_AND_UE_USAGE_SETTING_VALUE_STRUCT{
	uint8_t	voice_domain_pref;
	bool ue_usage_setting_value;
};
struct NAS_PROTOCOL_CONFIGURATION_STRUCT{
	uint16_t id;
	uint8_t len;
	uint8_t contents[80];					//248
};
/*
struct NAS_PROTOCOL_CONFIGURATION_OPTIONS_STRUCT{
	NAS_PROTOCOL_CONFIGURATION_STRUCT opt[5];
};*/
struct NAS_PDN_CONNECTIVITY_REQUEST_STRUCT{
	NAS_PROTOCOL_CONFIGURATION_STRUCT opt[5];	//83
	uint8_t eps_bearer_id;
	uint8_t procedure_transaction_id;
	uint8_t request_type;
	uint8_t pdn_type;
	bool eit;
	
};
struct NAS_ATTACH_REQUEST_STRUCT{
	NAS_VOICE_DOMAIN_PREF_AND_UE_USAGE_SETTING_VALUE_STRUCT voice_domain_pref_and_ue_usage_setting_value;
	NAS_NAS_KEY_SET_ID_STRUCT 			nas_ksi;
	NAS_EPS_MOBILE_ID_STRUCT 			eps_mobile_id;
	NAS_TRACKING_AREA_ID_STRUCT 		last_visited_registered_tai;
	NAS_DRX_PARAMETER_STRUCT			drx_param;
	NAS_UE_NETWORK_CAPABILITY_STRUCT 	ue_cap;
	NAS_MS_CLASSMARK2_STRUCT			ms_cm2;
	NAS_PDN_CONNECTIVITY_REQUEST_STRUCT		pdn_con_request;
	NAS_MS_NETWORK_CAPABILITY_VALUE_STRUCT		ms_net_cap;
	// char 						apn_name[40];//max:102
	char						apn_name[102];
	uint32_t					apn_len;
	bool 						ms_net_cap_present;
	bool						guti_type;
	bool						guti_type_present;
	bool						tmsi_flag;
	bool						tmsi_flag_present;
	bool 						last_visited_registered_tai_present;
	bool						drx_param_present;
	bool 						ue_cap_present;
	bool						ms_cm2_present;
	bool						voice_domain_pref_and_ue_usage_setting_value_present;
	uint8_t 					eps_attach_type;
//TODO: more optional things in this ATTACH REQUEST STRUCT
};
struct UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT{
	int emm_cause;
	uint8_t sqn_ms_xor_ak[6];
	uint8_t mac_s[8];
};
struct UPLINK_NAS_TRANSPORT_AUTHENTICATION_RESPONSE_STRUCT{
	uint8_t res[8];
};
struct UPLINK_NAS_TRANSPORT_SECURITY_MODE_COMPLETE_STRUCT{
	uint32_t len;
	uint8_t res[20];
};
struct UPLINK_NAS_TRANSPORT_ESM_INFORMATION_RESPONSE_STRUCT{
	uint32_t len;
	uint8_t apn_name[102];//max:102
};
union UPLINK_NAS_TRANSPORT_UNION{
	NAS_EPS_MOBILE_ID_STRUCT id;
	UPLINK_NAS_TRANSPORT_AUTHENTICATION_FAILURE_STRUCT af;
	UPLINK_NAS_TRANSPORT_AUTHENTICATION_RESPONSE_STRUCT res;
	UPLINK_NAS_TRANSPORT_SECURITY_MODE_COMPLETE_STRUCT sec_mode_com;
	UPLINK_NAS_TRANSPORT_ESM_INFORMATION_RESPONSE_STRUCT esm_info;
};
struct UPLINK_NAS_TRANSPORT_STRUCT{
	int request_type;
	UPLINK_NAS_TRANSPORT_UNION prop;
};
struct NAS_SERVICE_REQUEST_STRUCT{
	bool Service_Request_Flag;
	uint8_t KSI_and_sequence_number;
};
union NAS_INITIAL_UE_MESSAGE_UNION{
	NAS_ATTACH_REQUEST_STRUCT ar;
	NAS_SERVICE_REQUEST_STRUCT sr;
};
struct NAS_INITIAL_UE_MESSAGE_STRUCT{
	int request_type;
	NAS_INITIAL_UE_MESSAGE_UNION msg_type;
};
#endif
