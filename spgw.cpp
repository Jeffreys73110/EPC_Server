#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include "spgw.h"

void printf_tunnel_ctx(tunnel_ctx_t tct){
in_addr sin,sin1;
memcpy(&sin,&tct.enb_ipv4,4);
if(!tct.vec_nit.empty()){
memcpy(&sin1,&tct.vec_nit.at(0).ue_ipv4,4);
}
	printf("\x1B[32m##########################\n");
	printf("s11_mme_fteid: %08x\n",tct.s11_mme_fteid);
	printf("s11_sgw_fteid: %08x\n",tct.s11_sgw_fteid);
	printf("s1u_enb_fteid: %08x\n",tct.s1u_enb_fteid);
	printf("s1u_sgw_fteid: %08x\n",tct.s1u_sgw_fteid);
	printf("enb_ipv4: %s\n",inet_ntoa(sin));
if(!tct.vec_nit.empty()){
	printf("ue_ipv4: %s\n",inet_ntoa(sin1));
}
	printf("\x1B[0m");
}

/************************************************
 *
 * constants 
 *
 ************************************************/
spgw* spgw::m_instance=NULL;
pthread_mutex_t spgw_instance_mutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t spgw_enb_info_mutex=PTHREAD_MUTEX_INITIALIZER;

/************************************************
 *
 * constructor & get_instance 
 *
 ************************************************/
spgw::spgw(){}
spgw* spgw::get_instance(){
	pthread_mutex_lock(&spgw_instance_mutex);
	if(m_instance==NULL){
		m_instance=new spgw();
		m_instance->m_s1u_sgw_fteid=0x01000000;
		m_instance->m_s11_sgw_fteid=0x01000000;
		m_instance->init_s1u();
		m_instance->init_sgi();
		printf("new spgw\n");
	}
	pthread_mutex_unlock(&spgw_instance_mutex);
	return m_instance;
}
/************************************************
 *
 * init functions
 * 
 * init_sgi(): 
 *   I think it should use L2 protocol instead of
 * L3 protocol because it should send and recv L2
 * protocol.
 *
 ************************************************/
void spgw::init(){
}
void spgw::init_s1u(){
	m_s1u_soc=socket(AF_INET,SOCK_DGRAM,0);
	m_s1u_addr.sin_family=AF_INET;
	m_s1u_addr.sin_addr.s_addr=inet_addr("10.102.81.102");
	m_s1u_addr.sin_port=htons(2152);
	if((bind(m_s1u_soc,(sockaddr*)&m_s1u_addr,sizeof(m_s1u_addr)))==-1){
		printf("ms1u bind error\n");
	}
}
void spgw::init_sgi(){
	const int on=1;
	// socket rx/tx
	m_sgi_rx_soc=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	if(m_sgi_rx_soc<0){perror("m_sgi_rx"); return;}

	m_sgi_tx_soc=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
	if(m_sgi_tx_soc<0){perror("m_sgi_tx"); return;}
	
	if(setsockopt(m_sgi_tx_soc,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on))<0){
		perror("m_sgi_tx IP_HDRINCL"); return;
	}

	// not be used in init functions, but this will be used by other functions
	m_sgi_addr.sin_addr.s_addr = inet_addr("192.168.0.152");
	
/* 
//test send raw packet
uint8_t buf[84];
char buf_c[]="4500005489fb40004001f9720a6651640a66510b08000e1d0e620001da679b5b0000000099e90d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";
printf("sizeof(c):%lu\n",strlen(buf_c));

c2u(buf,buf_c,84);
sockaddr_in sin;
sin.sin_family=AF_INET;
sin.sin_port=htons(10000);
sin.sin_addr.s_addr=inet_addr("10.102.81.11");
	sendto(m_sgi_tx_soc,buf,84,0,(sockaddr*)&sin,sizeof(sockaddr));
*/
/* bind eth0
	strncpy((char*)ifr.ifr_name,"eth0",IFNAMSIZ);
	if((ioctl(m_sgi_soc,SIOCGIFINDEX,&ifr))==-1){
		printf("get if index error\n");
	}
	sll.sll_family=PF_PACKET;
	sll.sll_ifindex=ifr.ifr_ifindex;
	sll.sll_protocol=htons(ETH_P_IP);


	if(setsockopt(m_sgi_soc, SOL_SOCKET, SO_REUSEADDR, (char *)&socopt, sizeof(socopt)) < 0){
		perror("setsockopt()");
	}
*/
/*
	if((bind(m_sgi_soc,(sockaddr*)&sll,sizeof(sll)))==-1){
		perror("bind error!");
	}
*/
}
void* thread_send_echo_request(void* arg){
	spgw* spgw=spgw::get_instance();
	int i=0;
	while(1){
		pthread_mutex_lock(&spgw_enb_info_mutex);

		spgw->send_echo_request();
		printf("send_echo_request\n");

		pthread_mutex_unlock(&spgw_enb_info_mutex);
		sleep(60);
	}
}
void spgw::send_echo_request(){
printf("###############################\nspgw: send_echo_request\n");
	uint8_t buf[]={0x32,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	int len,i;
	if(!m_enb_info.empty()){
		for(i=0;i<m_enb_info.size();i++){
			len=sendto(m_s1u_soc,buf,12,0,(sockaddr*)&m_enb_info.at(i),sizeof(sockaddr_in));
			printf("send_echo_requst\n");
			if(len<0) printf("   send echo request error!\n");
		}
	}
}
void spgw::gtpu_write_header(uint8_t* msg,int len,uint32_t teid){
	uint8_t* ptr=(uint8_t*)&len;
	msg[0]=0x30;	//GTPv1, Plain message
	msg[1]=0xff;	//Plain message
	msg[2]=*ptr; ptr++;
	msg[3]=*ptr;
	memcpy(&msg[4],&teid,4);
}

uint32_t spgw::get_next_s11_sgw_fteid(){
	//return m_s11_sgw_fteid++;
	return m_s11_sgw_fteid;
}
uint32_t spgw::get_next_s1u_sgw_fteid(){
	//return m_s1u_sgw_fteid++;
	return m_s1u_sgw_fteid;
}
uint32_t spgw::get_s1u_addr_ipv4(){
	return m_s1u_addr.sin_addr.s_addr;
}

void spgw::manage_create_session_request(uint32_t s11_mme_fteid,int bearer_id,int qCI,uint32_t* s11_sgw_fteid,uint32_t* s1u_sgw_fteid){
//There's more informations here
//maybe you nees eps bearer id, imsi or other
	*s11_sgw_fteid = get_next_s11_sgw_fteid();
	*s1u_sgw_fteid = get_next_s1u_sgw_fteid();

	tunnel_ctx_t ni;
	ni.s11_mme_fteid = s11_mme_fteid;
	ni.s11_sgw_fteid = *s11_sgw_fteid;
	ni.s1u_sgw_fteid = *s1u_sgw_fteid;

	m_s1u_sgw_fteid_to_s11_sgw_fteid.insert(std::pair<uint32_t,uint32_t>(ni.s1u_sgw_fteid,ni.s11_sgw_fteid));
printf("create session: \n");
	m_s11_sgw_fteid_to_tunnel_ctx.insert(std::pair<uint32_t,tunnel_ctx_t>(ni.s11_sgw_fteid,ni));
}
void spgw::manage_end_session_request(uint32_t global_fteid){
	m_s1u_sgw_fteid_to_s11_sgw_fteid.erase(global_fteid);
	printf("End session: \n");
	m_s11_sgw_fteid_to_tunnel_ctx.erase(global_fteid);
}
void spgw::manage_modify_bearer_request(uint32_t s11_sgw_fteid,erab_setuplistctxtsures_t est){
	std::map<uint32_t,tunnel_ctx_t>::iterator it = m_s11_sgw_fteid_to_tunnel_ctx.find(s11_sgw_fteid);
	if(it == m_s11_sgw_fteid_to_tunnel_ctx.end()){
		printf("manage modify bearer request: doesn't find s11_sgw\n");
		return ;
	}
	tunnel_ctx_t* ni = &it->second;
	ni->s1u_enb_fteid = est.s1u_enb_fteid;
	ni->enb_ipv4 = est.enb_ipv4;
	ni->ebi = est.ebi;

	sockaddr_in enb_info;
	enb_info.sin_family = AF_INET;
	enb_info.sin_addr.s_addr = est.enb_ipv4;
	enb_info.sin_port = htons(2152);

	pthread_mutex_lock(&spgw_enb_info_mutex);
	m_enb_info.push_back(enb_info);
	pthread_mutex_unlock(&spgw_enb_info_mutex);
}
void spgw::manage_s1u_pdu(uint8_t* msg,sockaddr_in* sin,int* len){
	in_addr this_ip;
	this_ip.s_addr = inet_addr("192.168.0.152");

	ip* iphdr = (ip*)&msg[GTPV1_LEN]; 
	tcphdr* tcp;
	udphdr* udp;
	*len=msg[2]*256+msg[3];

	// extrace fteid
	uint32_t s1u_sgw_fteid;
	memcpy(&s1u_sgw_fteid,&msg[4],4); //TODO: change 4 to TEID_POS
	
	// Record Out NAT information
	nat_information_t nit;
	memcpy(&nit.ue_ipv4,&iphdr->ip_src,4);
	memcpy(&nit.out_ipv4,&iphdr->ip_dst,4);
	memcpy(&nit.proto,&iphdr->ip_p,1);

	// Distinguish TCP from UDP
	if(iphdr->ip_p==IPPROTO_TCP){			//IPPROTO_TCP:6
		tcp = (tcphdr*)&msg[GTPV1_LEN+sizeof(ip)];
		memcpy(&nit.ue_port,&tcp->th_sport,2);
		memcpy(&nit.out_port,&tcp->th_dport,2);
	}
	else if(iphdr->ip_p==IPPROTO_UDP){		//IPPROTO_UDP:17
		udp = (udphdr*)&msg[GTPV1_LEN+sizeof(ip)];
		memcpy(&nit.ue_port,&udp->uh_sport,2);
		memcpy(&nit.out_port,&udp->uh_dport,2);
	}
	else{
		printf("warning: s1u get unsupported L4 protocol %d\n",iphdr->ip_p);
	}
	nit.time_stamp = time(NULL);
	
	// make key of map "m_out_ip_port_to_s1u_enb_fteid" (see spgw.h for what it works)
	uint64_t out_ip_port = nit.out_ipv4;
	out_ip_port <<= 32;
	if(nit.proto == IPPROTO_TCP){
		out_ip_port += NAT_IPPROTO_TCP_OFFSET;
		out_ip_port += nit.out_port;
	}
	else if(nit.proto == IPPROTO_UDP){
		out_ip_port += NAT_IPPROTO_UDP_OFFSET;
		out_ip_port += nit.out_port;
	}
	else{
		out_ip_port += nit.proto;
	}
	/* one part of the main concept of my NAT, didn't tested
	do{
		auto iter = m_out_ip_port_to_s1u_enb_fteid.find(out_ip_port);
		if(iter!=m_out_ip_port_to_s1u_enb_fteid.end()){
			out_ip_port += NAT_IPPROTO_GAP;
		}
	}while(1);
	*/

	// find tunnel ctx by s1u_sgw_fteid to get s1u_enb_fteid (recorded in tunnel ctx)
	std::map<uint32_t,uint32_t>::iterator iter = m_s1u_sgw_fteid_to_s11_sgw_fteid.find(s1u_sgw_fteid);
	//printf("\x1B[34ms1u_sgw_fteid:%08x\x1B[0m\n",s1u_sgw_fteid);
	if(iter == m_s1u_sgw_fteid_to_s11_sgw_fteid.end()){
		printf("spgw: can't find s11_sgw_fteid by s1u_sgw_fteid\n");
		return;
	}
	std::map<uint32_t,tunnel_ctx_t>::iterator jter = m_s11_sgw_fteid_to_tunnel_ctx.find(iter->second);
	if(jter == m_s11_sgw_fteid_to_tunnel_ctx.end()){
		printf("spgw: can't find tunnel_ctx by s11_sgw_fteid\n");
		return;
	}
	// insert s11_sgw_fteid to map to make finding easy
	m_out_ip_port_to_s11_sgw_fteid.insert(std::pair<uint64_t,uint32_t>(out_ip_port,jter->second.s11_sgw_fteid));
	jter->second.vec_nit.push_back(nit);

	// Change Sockaddr
	sin->sin_family = AF_INET;
	sin->sin_port = nit.out_port;
	sin->sin_addr.s_addr = nit.out_ipv4;

	// Change IP Layer Header
	iphdr->ip_src = this_ip;
	iphdr->ip_sum = modify_checksum(iphdr->ip_sum,nit.ue_ipv4,this_ip.s_addr);

	// Change Transport Layer Header
	if(iphdr->ip_p==IPPROTO_TCP){
		tcp->th_sum = modify_checksum(tcp->th_sum,nit.ue_ipv4,this_ip.s_addr);
	}
	else if(iphdr->ip_p==IPPROTO_UDP){
		udp->uh_sum = modify_checksum(udp->uh_sum,nit.ue_ipv4,this_ip.s_addr);
	}

}
void spgw::manage_sgi_write_gtp_header(uint8_t* msg,short len,uint32_t s1u_enb_fteid){
	msg[0] = 0x30; //GTPv1
	msg[1] = 0xff; //T-PDU
	memcpy(&msg[2],&len,2);
	memcpy(&msg[4],&s1u_enb_fteid,4);
}
void spgw::manage_sgi_pdu(uint8_t* msg){
	ip* iphdr = (ip*)&msg[14];
	if(!memcmp(&iphdr->ip_dst,&m_sgi_addr.sin_addr,4)){
		//printf("sgi_input: iphdr=%s\n",inet_ntoa(iphdr->ip_dst));
		tcphdr* tcp;
		udphdr* udp;

		// make out_ip_port
		uint64_t out_ip_port = iphdr->ip_src.s_addr;
		out_ip_port<<=32;
		if(iphdr->ip_p == IPPROTO_TCP){
			tcp = (tcphdr*) &msg[14+sizeof(ip)];
			out_ip_port += NAT_IPPROTO_TCP_OFFSET;
			out_ip_port += tcp->th_sport;
		}
		else if(iphdr->ip_p == IPPROTO_UDP){
			udp = (udphdr*) &msg[14+sizeof(ip)];
			out_ip_port += NAT_IPPROTO_UDP_OFFSET;
			out_ip_port += udp->uh_sport;
		}
		else{
			out_ip_port += iphdr->ip_p;
		}

		// do search
		std::map<uint64_t,uint32_t>::iterator it = m_out_ip_port_to_s11_sgw_fteid.find(out_ip_port);
		if(it == m_out_ip_port_to_s11_sgw_fteid.end()) {printf("sgi pdu no out_ip_port:%016lx\n",out_ip_port);return;}

		std::map<uint32_t,tunnel_ctx_t>::iterator jt = m_s11_sgw_fteid_to_tunnel_ctx.find(it->second);
		if(jt == m_s11_sgw_fteid_to_tunnel_ctx.end()) {printf("sgi pdu no tunnel_ctx\n"); return;}

		if(jt->second.vec_nit.empty()) {printf("vec_nit is empty\n"); return;}

		// FIXME: Use all elements in vec_nit instead of only the first one
		// change L7(TCP/UDP) checksum
		if(iphdr->ip_p==IPPROTO_TCP){
			tcp->th_sum = modify_checksum(tcp->th_sum,iphdr->ip_dst.s_addr,jt->second.vec_nit.at(0).ue_ipv4);
		}
		else if(iphdr->ip_p==IPPROTO_UDP){
			udp->uh_sum = modify_checksum(udp->uh_sum,iphdr->ip_dst.s_addr,jt->second.vec_nit.at(0).ue_ipv4);
		}

		// change L6(IP) checksum/dst_ip
		iphdr->ip_sum = modify_checksum(iphdr->ip_sum,iphdr->ip_dst.s_addr,jt->second.vec_nit.at(0).ue_ipv4);
		iphdr->ip_dst.s_addr = jt->second.vec_nit.at(0).ue_ipv4;

		// write L5(GTP) header
		manage_sgi_write_gtp_header(&msg[6],iphdr->ip_len,jt->second.s1u_enb_fteid);

		// send out (L3/L4 information)
		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(2152);
		sin.sin_addr.s_addr = jt->second.enb_ipv4;
		//printf("sgi_send_to_s1u_sin:%s\n",inet_ntoa(sin.sin_addr));
		
		sendto(m_s1u_soc,&msg[6],htons(iphdr->ip_len)+8,0,(sockaddr*)&sin,sizeof(sockaddr));
	}
	return;
}
void spgw::run(){
	pthread_t pid;
	pthread_create(&pid,NULL,thread_send_echo_request,NULL);
	sockaddr_in src_addrin;
	sockaddr_ll src_addrll;
	fd_set set;
	uint8_t msg[4000];
	int len,n,i,s1ulen;
	int laaa=0;
	uint32_t addrlen=sizeof(sockaddr);
	printf("spgw run!\n");
	
	int max_fd=(m_sgi_rx_soc>m_s1u_soc)?m_sgi_rx_soc:m_s1u_soc;
	while(1){
		FD_ZERO(&set);
		FD_SET(m_sgi_rx_soc,&set);
		//FD_SET(m_s1u_if,&set);
		FD_SET(m_s1u_soc,&set);
		int n=select(max_fd+1,&set,NULL,NULL,NULL);
		if(n<0){printf("spgw select error\n");}
		else if(n){
			if(FD_ISSET(m_s1u_soc,&set)){
				len=recvfrom(m_s1u_soc,msg,3999,0,(sockaddr*)&src_addrin,&addrlen);
				printf("recvfrom s1u, from: %s, len:%d\n",inet_ntoa(src_addrin.sin_addr),len);
				//echo request  GTP echo request的[1]欄位為0x01(固定格式)
				if(msg[1]==0x01){
					msg[1]=0x02;
					msg[3]=0x06;
					msg[10]=0x00;
					msg[11]=0x00;
					msg[12]=0x0e;
					msg[13]=0x00;
					len=sendto(m_s1u_soc,msg,14,0,(sockaddr*)&src_addrin,sizeof(src_addrin));
				}
                if(msg[1]==0xff){   //轉送 將s1u介面收到的封包轉送至SGi介面
					manage_s1u_pdu(msg,&src_addrin,&s1ulen);
					len=sendto(m_sgi_tx_soc,&msg[8],s1ulen,0,(sockaddr*)&src_addrin,sizeof(src_addrin));
					printf("sendto: %d %s\n",len,inet_ntoa(src_addrin.sin_addr));
					if(len<0)perror("s1u sendto");
				}
				printf("\n");
			}
			if(FD_ISSET(m_sgi_rx_soc,&set)){	//轉送 將SGi介面收到的封包轉送至s1u介面
				len=recvfrom(m_sgi_rx_soc,&msg[0],3999,0,(sockaddr*)&src_addrll,&addrlen);
				manage_sgi_pdu(msg);
			}
		}
		
	}
	
}
/*
int main(){
	spgw* spgw=spgw::get_instance();
	spgw->init();
	spgw->run();
}*/
