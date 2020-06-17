#ifndef __S1AP_COMMON_H_INCLUDED__
#define __S1AP_COMMON_H_INCLUDED__

#define max_served_num 10
#include "nas_common.h"
#include <stdint.h>
typedef unsigned char uchar;
uint8_t c2u(char);
void c2u(uint8_t*,char*,int);
uint32_t modify_checksum_add(uint16_t cs,uint32_t a);
uint16_t modify_checksum(uint16_t ori_cs,uint32_t ori_ip,uint32_t new_ip);
uint16_t modify_port_checksum(uint16_t ori_cs, uint32_t ori_ip, uint32_t new_ip, uint16_t ori_port,uint16_t new_port);
/* eNodeB should not be put here but maybe lte_common.h or other */
enum eNodeB_state{
        ENODEB_UNREGISTERED,
        ENODEB_REGISTERED,
};
enum eNodeB_type{
        ENODEB_TYPE_HOMEENB,
        ENODEB_TYPE_MACROENB,
        ENODEB_TYPE_OTHER
};
struct enb_ctx_t{
	eNodeB_state	state;
	int		type;
	int		UE_NUM;
	char		IP[20];
	uint32_t	UE_LIST[10];
	char		pLMN[7];
	char		MNC[4];
	char		MCC[4];
	uint32_t	homeENB_ID;
	uint32_t	macroENB_ID;
	char		name[151];
	int			len_broadcastpLMNs;
	char		broadcastpLMNs[10][6][7];
	int			len_TAC;
	char		TAC[10][5];
	uint8_t		PagingDRX;
	void		print_properties();
};
struct erab_setuplistctxtsures_t{
	int ebi;
	uint32_t enb_ipv4;
	uint32_t s1u_enb_fteid;
};
struct s1ap_args_t{
	char 	MMEname[100];
        char 	Served_pLMN[max_served_num][7];
        int 	Served_MME_Group_ID[max_served_num];      
        int 	Served_MME_Code[max_served_num];           
        int 	len_ServedGUMMEIs;
        int 	len_ServedpLMNs;    
        int 	len_ServedGroupID;
        int 	len_ServedMMECs;
        char 	RelativeMMECapacity;
};
/* UE should not be put here(S1AP) but maybe lte_common.h or other */

struct ue_ecm_ctx_t{
};
enum ue_state_t{
        UE_UNREGISTERED,
        REGISTERED,
};
struct ue_sec_ctx_t{
	uint8_t k_asme[32];
	uint8_t k_nasenc[32];
	uint8_t k_nasint[32];
	uint8_t k_enb[32];
	uint8_t rand[16];
	uint8_t sqn[6];
	uint8_t res[8];
	uint8_t int_al;
	uint8_t enc_al;
	uint32_t dl_count;
	uint32_t ul_count;
};
struct ue_erab_ctx_t{
	uint32_t s11_mme_fteid;
	uint32_t s11_sgw_fteid;
	uint32_t s1u_enb_fteid;
	uint32_t s1u_sgw_fteid;
	uint32_t s1u_ipv4;
	uint32_t pdn_ipv4;
	uint32_t ims_ipv4;
};
struct packet_filter_t
{
	uint8_t		direction;	// 1:downlink, 2:uplink, 3:bi-directional
	uint32_t 	remote_ip;
	uint32_t 	remote_ip_mask;
	uint8_t		protocol;	// IP protocol numbers of IP header as directed by RFC 790
	uint16_t 	LPort;
	uint16_t 	RPort;
};

struct traffic_flow_template_t
{
#define	TFT_PK_NUM	4
	int	filter_num;
	packet_filter_t filter[TFT_PK_NUM];
	uint8_t	imsi[15];

	traffic_flow_template_t()
	{
		memset(this, 0, sizeof(traffic_flow_template_t));
		filter_num = TFT_PK_NUM;
	}
};

#define	UE_eRAB_Ctx_SIZE	15
struct ue_ctx_t{
	NAS_INITIAL_UE_MESSAGE_STRUCT prop;
	uint32_t	eNB_UE_ID;
	uint32_t	MME_UE_ID;
	ue_state_t	state;
	bool		REGISTERED;
	ue_sec_ctx_t	sec;
	ue_erab_ctx_t	erab[UE_eRAB_Ctx_SIZE];
	uint8_t UERadioCapability_ctx_t[300];
	traffic_flow_template_t	erab_tft;
	void init();
};
struct NEXT_MESSAGE_STRUCT{
	ue_ctx_t* temp_ue;
	int type;
};
#endif
