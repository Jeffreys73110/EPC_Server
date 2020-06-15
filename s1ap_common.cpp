#include <string.h>
#include <netinet/in.h>

#include "s1ap_common.h"
#include<stdio.h>
uint8_t c2u(char s){
	if(s>96) return s-87;
	if(s>64) return s-55;
	if(s>47) return s-48;
}
void c2u(uint8_t* buf,char* s,int l){
	int i;
	for(i=0;i<l;i++)
		buf[i]=c2u(s[i*2])*16+c2u(s[i*2+1]);
}
uint32_t modify_checksum_add(uint16_t s,uint32_t a){
	uint32_t cs=s;
	if((cs+a)&0x80000000){
		a--;
		cs=(cs+a)&0x0000ffff;
	}
	else{
		cs+=a;
		if(cs>0xffff){
			cs++;
			cs=cs&0xffff;
		}
	}
	return cs;
}
uint16_t modify_checksum(uint16_t ori_cs,uint32_t ori_ip,uint32_t new_ip){
	uint16_t checksum;
	ori_cs=ntohs(ori_cs);

	uint32_t ori_ip_n=ntohl(ori_ip);
	uint32_t new_ip_n=ntohl(new_ip);

	uint32_t ori_ip_n_a=(ori_ip_n>>16);
	uint32_t new_ip_n_a=(new_ip_n>>16);
	ori_ip_n_a-=new_ip_n_a;
	checksum=modify_checksum_add(ori_cs,ori_ip_n_a);

	uint32_t ori_ip_n_b=(ori_ip_n&0xffff);
	uint32_t new_ip_n_b=(new_ip_n&0xffff);
	ori_ip_n_b-=new_ip_n_b;
	checksum=modify_checksum_add(checksum,ori_ip_n_b);

	return htons(checksum);
}
uint16_t checksum(uint8_t* s,int len,int offset){
	uint16_t* ps=(uint16_t*)s;
	uint32_t sum=0;
	for(int i=0;i<len/2;i++){
		if(i==offset) continue;
		sum+=(ps[i]>>8)+((ps[i]<<8)&0xff00);
		printf("%05x \n",sum);
	}
	sum=(sum&0xffff)+(sum>>16);
	memcpy(&ps[offset],&sum,2);
	return ~sum;
}
void enb_ctx_t::print_properties(){
        printf("#######        eNB  info   #########\n");
        printf("type: %d\n",type);
        printf("name: %s\n",name);
		printf("IP:   %s\n",IP);
        printf("pLMN: %s\n",pLMN);
        printf("MNC: %s\n",MNC);
        printf("MCC: %s\n",MCC);
        printf("macroENB_ID: %2x\n",macroENB_ID);
        printf("homeENB_ID: %2x\n",homeENB_ID);
        int i,j;
        printf("@@ TAC and broadcastpLMNs @@\n");
        for(i=0;i<len_TAC;i++){
                printf("\titem_num: %d\n",i);
                printf("\tTAC: %s\n",TAC[i]);
                for(j=0;j<len_broadcastpLMNs;j++){
                        printf("\t\tbroadcastpLMNs: %d\n",j);
                        printf("\t\t%s\n",broadcastpLMNs[i][j]);
                }
        }
        printf("PagingDRX: v");
        printf("%d\n",32<<PagingDRX);
		printf("UE_NUM:%d\n",UE_NUM);
}

