#ifndef __F1_H__
#define __F1_H__
#include <stdint.h>
#include "../s1ap_common.h"
void get_res_autn_k_asme(uint8_t[],uint8_t[],uint8_t[],uint8_t[],uint8_t[]);
void resync(uint8_t* sqn_ms_xor_ak,uint8_t* rand,uint8_t* sqn);
void init_k_int_enc(uint8_t[],uint8_t[],uint8_t[],int,int);
uint8_t* do_EIA1(uint8_t[],uint8_t*,int,int,uint32_t*);
void get_k_enb(ue_ctx_t*,uint8_t*);
void get_Next_Hop(ue_ctx_t* ue,uint8_t* NH);
void get_k_enb_star(ue_ctx_t*,uint8_t*);
#endif
