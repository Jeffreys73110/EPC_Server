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
#include "Func.h"

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
		m_instance->m_s1u_sgw_fteid=0x00000000;
		m_instance->m_s11_sgw_fteid=0x00000000;
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
	m_s1u_addr.sin_addr.s_addr=inet_addr(SGW_IP);
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
	m_sgi_addr.sin_addr.s_addr = inet_addr(PGW_IP);
	
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
	m_s11_sgw_fteid += 0x01000000;
	return m_s11_sgw_fteid;
	//return m_s11_sgw_fteid;
}
uint32_t spgw::get_next_s1u_sgw_fteid(){
	m_s1u_sgw_fteid += 0x01000000;
	return m_s1u_sgw_fteid;
	//return m_s1u_sgw_fteid;
}
uint32_t spgw::get_s1u_addr_ipv4(){
	return m_s1u_addr.sin_addr.s_addr;
}

void spgw::manage_create_session_request(uint32_t s11_mme_fteid,int bearer_id,int qCI,uint32_t* s11_sgw_fteid,uint32_t* s1u_sgw_fteid){
//There's more informations here
//maybe you nees eps bearer id, imsi or other
	*s11_sgw_fteid = get_next_s11_sgw_fteid();
	*s1u_sgw_fteid = get_next_s1u_sgw_fteid();
	printf("yyyyyyyy%02xyyyyyyyyyyyy\n",m_s1u_sgw_fteid);
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
	LINE_TRACE();
	std::map<uint32_t,tunnel_ctx_t>::iterator it = m_s11_sgw_fteid_to_tunnel_ctx.find(s11_sgw_fteid);
	if(it == m_s11_sgw_fteid_to_tunnel_ctx.end()){
		LINE_TRACE();
		printf("manage modify bearer request: doesn't find s11_sgw\n");
		RETURN;
	}
	TestMsg_TRACE("\033[1;34m manage_modify_bearer_request, s11_sgw_fteid=%08x, est.s1u_enb_fteid = %08x\033[0m, %d @ %s\n", htonl(s11_sgw_fteid), htonl(est.s1u_enb_fteid), __LINE__, __FILE__);
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
	RETURN;
}
void spgw::manage_s1u_pdu(uint8_t* msg,sockaddr_in* sin,int* len){
	printf("\n\n\n--- s1u input -----------------------------------------\n");
	LINE_TRACE();
	in_addr this_ip;
	this_ip.s_addr = inet_addr(PGW_IP);
	int big_udp_flag=0;

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
	nit.time_stamp = time(NULL);

	// Distinguish TCP from UDP
	if(iphdr->ip_p==IPPROTO_TCP)	//IPPROTO_TCP:6
	{			
		tcp = (tcphdr*)&msg[GTPV1_LEN+sizeof(ip)];
		memcpy(&nit.ue_port,&tcp->th_sport,2);
		memcpy(&nit.out_port,&tcp->th_dport,2);
	}
	else if(iphdr->ip_p==IPPROTO_UDP)		//IPPROTO_UDP:17
	{
		printf("Flags: 0x%04x\n", iphdr->ip_off);
		udp = (udphdr*)&msg[GTPV1_LEN+sizeof(ip)];
		if (ntohs(iphdr->ip_off)==IP_DF || ntohs(iphdr->ip_off)==IP_MF || iphdr->ip_off==0)
		{
			memcpy(&nit.ue_port,&udp->uh_sport,2);
			memcpy(&nit.out_port,&udp->uh_dport,2);
			LINE_TRACE(); 
			TestMsg_TRACE("nit.ue_port=0x%x (%d), nit.out_port=0x%x (%d)\n", nit.ue_port, nit.ue_port, nit.out_port, nit.out_port);
			m_s1u_udp_port.insert(std::pair<short unsigned int, short unsigned int>(iphdr->ip_id, udp->uh_sport));
		}
		else
		{
			std::map<short unsigned int,short unsigned int>::iterator ipo = m_s1u_udp_port.find(iphdr->ip_id);
			memcpy(&nit.ue_port,&ipo->second,2);
			big_udp_flag = 1;
		}

	}
	else
	{
		printf("warning: s1u get unsupported L4 protocol %d\n",iphdr->ip_p);
	}


	// find tunnel ctx by s1u_sgw_fteid to get s1u_enb_fteid (recorded in tunnel ctx)
	std::map<uint32_t,uint32_t>::iterator iter = m_s1u_sgw_fteid_to_s11_sgw_fteid.find(s1u_sgw_fteid);
	printf("\x1B[34ms1u_sgw_fteid:%08x\x1B[0m\n",s1u_sgw_fteid);
	printf("kk_flag: %d\n",big_udp_flag);
	if(iter == m_s1u_sgw_fteid_to_s11_sgw_fteid.end()){
		printf("spgw: can't find s11_sgw_fteid by s1u_sgw_fteid\n");
		RETURN;
	}
	std::map<uint32_t,tunnel_ctx_t>::iterator jter = m_s11_sgw_fteid_to_tunnel_ctx.find(iter->second);
	if(jter == m_s11_sgw_fteid_to_tunnel_ctx.end()){
		printf("spgw: can't find tunnel_ctx by s11_sgw_fteid\n");
		RETURN;
	}



	// set external ip and port
	nit.pgw_ipv4 = this_ip.s_addr;
	nit.pgw_port = nit.ue_port + (uint16_t)(jter->second.s11_sgw_fteid >> 15);
	TestMsg_TRACE("nit.pgw_port=%04x, nit.ue_port=%04x, s11_sgw_fteid=%04x, %d @ %s\n", nit.pgw_port, nit.ue_port, (uint16_t)(jter->second.s11_sgw_fteid >> 15), __LINE__, __FILE__);

	TestMsg_TRACE("nit.ue_ipv4=0x%08x, nit.ue_port=0x%04x, nit.pgw_ipv4=0x%08x, nit.pgw_port=0x%04x, nit.out_ipv4=0x%08x, nit.out_port=0x%04x, %d @ %s\n", 
		ntohl(nit.ue_ipv4),
		ntohs(nit.ue_port), 
		ntohl(nit.pgw_ipv4),
		ntohs(nit.pgw_port), 
		ntohl(nit.out_ipv4),
		ntohs(nit.out_port),
		__LINE__, __FILE__);

	// Change Sockaddr
	sin->sin_family = AF_INET;
	sin->sin_port = nit.out_port;
	sin->sin_addr.s_addr = nit.out_ipv4;


	iphdr->ip_src.s_addr = nit.pgw_ipv4;
	iphdr->ip_sum = modify_checksum(iphdr->ip_sum,nit.ue_ipv4,nit.pgw_ipv4);

	if(big_udp_flag)	{RETURN;}

	LINE_TRACE();
	// Change Transport Layer Header
	if(iphdr->ip_p==IPPROTO_TCP){
		
		tcp->th_sport = nit.pgw_port;
		tcp->th_sum = modify_port_checksum(tcp->th_sum, nit.ue_ipv4, nit.pgw_ipv4, nit.ue_port, nit.pgw_port);
	}

	else if(iphdr->ip_p==IPPROTO_UDP){
		printf("UDP checksum: %5u\n",ntohs(udp->uh_sum));
		if(big_udp_flag!=1){
			udp->uh_sport = nit.pgw_port;
			udp->uh_sum = modify_port_checksum(udp->uh_sum, nit.ue_ipv4, nit.pgw_ipv4, nit.ue_port, nit.pgw_port);
		}
		else
			printf("UDP not modify checksum\n");
		printf("UDP modify checksum: %5u\n",ntohs(udp->uh_sum));
	}

	// make key of map "m_out_ip_port_to_s1u_enb_fteid" (see spgw.h for what it works)
	uint64_t out_ip_port = this_ip.s_addr;
	out_ip_port <<= 32;
	if(nit.proto == IPPROTO_TCP){
		out_ip_port += NAT_IPPROTO_TCP_OFFSET;
		// out_ip_port += nit.out_port;
		out_ip_port += nit.pgw_port;
	}
	else if(nit.proto == IPPROTO_UDP){
		out_ip_port += NAT_IPPROTO_UDP_OFFSET;
		// out_ip_port += nit.out_port;
		out_ip_port += nit.pgw_port;
	}
	else{
		out_ip_port += nit.proto;
	}
	
	if( iphdr->ip_p==IPPROTO_UDP && nit.ue_port==htons(5060))
	{
		TestMsg_TRACE("\033[1;35m manage_s1u_pdu, out_ip_port = %016lx\033[0m, %d @ %s\n", out_ip_port, __LINE__, __FILE__);
	}

	// insert s11_sgw_fteid to map to make finding easy
	std::map<uint64_t,uint32_t>::iterator itt = m_out_ip_port_to_s11_sgw_fteid.find(out_ip_port);
	if (itt != m_out_ip_port_to_s11_sgw_fteid.end())	m_out_ip_port_to_s11_sgw_fteid.erase(itt);
	m_out_ip_port_to_s11_sgw_fteid.insert(std::pair<uint64_t,uint32_t>(out_ip_port,jter->second.s11_sgw_fteid));
	
	// for (std::map<uint64_t,uint32_t>::iterator itt=m_out_ip_port_to_s11_sgw_fteid.begin(); itt!=m_out_ip_port_to_s11_sgw_fteid.end(); ++itt)	printf("manage_s1u_pdu - m_out_ip_port_to_s11_sgw_fteid => %016lx --> %08x\n", itt->first, htonl(itt->second));

	// insert nat_information to map to make finding easy
	std::map<uint64_t,nat_information_t>::iterator itn = m_out_ip_port_to_nat_info.find(out_ip_port);
	if (itn != m_out_ip_port_to_nat_info.end())	m_out_ip_port_to_nat_info.erase(itn);
	m_out_ip_port_to_nat_info.insert(std::pair<uint64_t,nat_information_t>(out_ip_port, nit));
	

	RETURN;
}
void spgw::manage_sgi_write_gtp_header(uint8_t* msg,short len,uint32_t s1u_enb_fteid){
	msg[0] = 0x30; //GTPv1
	msg[1] = 0xff; //T-PDU
	memcpy(&msg[2],&len,2);
	memcpy(&msg[4],&s1u_enb_fteid,4);
}
void spgw::manage_sgi_pdu(uint8_t* msg){
	ip* iphdr = (ip*)&msg[14];
	int b_flag=0;
	if(!memcmp(&iphdr->ip_dst,&m_sgi_addr.sin_addr,4))
	{
		printf("\n\n\n--- sgi input: iphdr=%s Flag:%x-----------------------------------------\n",inet_ntoa(iphdr->ip_dst),ntohs(iphdr->ip_off));
		LINE_TRACE();
				
		tcphdr* tcp;
		udphdr* udp;

		uint64_t out_ip_port = iphdr->ip_dst.s_addr;
		out_ip_port<<=32;
		if(iphdr->ip_p == IPPROTO_TCP){
			LINE_TRACE();
			tcp = (tcphdr*) &msg[14+sizeof(ip)];
			out_ip_port += NAT_IPPROTO_TCP_OFFSET;
			out_ip_port += tcp->th_dport;
		}
		else if(iphdr->ip_p == IPPROTO_UDP){
			LINE_TRACE();
			printf("Flags: 0x%04x\n", ntohs(iphdr->ip_off));
			udp = (udphdr*) &msg[14+sizeof(ip)];

			if (ntohs(iphdr->ip_off)==IP_DF || ntohs(iphdr->ip_off)==IP_MF || iphdr->ip_off==0)
			{
				LINE_TRACE();
				out_ip_port += udp->uh_dport;
				m_sgi_udp_port.insert(std::pair<short unsigned int, short unsigned int>(iphdr->ip_id, udp->uh_dport));
			}
			else
			{
				LINE_TRACE();
				std::map<short unsigned int,short unsigned int>::iterator ipo = m_sgi_udp_port.find(iphdr->ip_id);
				out_ip_port += ipo->second;
				b_flag+=1;
			}
			out_ip_port += NAT_IPPROTO_UDP_OFFSET;
		}
		else
		{
			LINE_TRACE();
			out_ip_port += iphdr->ip_p;
		}
		if(iphdr->ip_p == IPPROTO_UDP)
		{
			if (udp->uh_dport==htons(5060))
				TestMsg_TRACE("\033[1;35m manage_sgi_pdu, out_ip_port = %016lx\033[0m, %d @ %s\n", out_ip_port, __LINE__, __FILE__);
		}
		// do search
		std::map<uint64_t,uint32_t>::iterator it = m_out_ip_port_to_s11_sgw_fteid.find(out_ip_port);
		if(it == m_out_ip_port_to_s11_sgw_fteid.end()) {printf("sgi pdu no out_ip_port:%016lx\n",out_ip_port);RETURN;}

		std::map<uint32_t,tunnel_ctx_t>::iterator jt = m_s11_sgw_fteid_to_tunnel_ctx.find(it->second);
		if(jt == m_s11_sgw_fteid_to_tunnel_ctx.end()) {printf("sgi pdu no tunnel_ctx\n"); RETURN;}
		tunnel_ctx_t *pni = &jt->second;

		std::map<uint64_t,nat_information_t>::iterator itn = m_out_ip_port_to_nat_info.find(out_ip_port);
		if (itn == m_out_ip_port_to_nat_info.end())	{printf("m_out_ip_port_to_nat_info has no the out_ip_port=%016lx\n", out_ip_port); RETURN;}
		nat_information_t	nit = itn->second;

		TestMsg_TRACE("nit.ue_ipv4=0x%08x, nit.ue_port=0x%04x, nit.pgw_ipv4=0x%08x, nit.pgw_port=0x%04x, nit.out_ipv4=0x%08x, nit.out_port=0x%04x, %d @ %s\n", 
			ntohl(nit.ue_ipv4),
			ntohs(nit.ue_port), 
			ntohl(nit.pgw_ipv4),
			ntohs(nit.pgw_port), 
			ntohl(nit.out_ipv4),
			ntohs(nit.out_port),
			__LINE__, __FILE__);

		// FIXME: Use all elements in vec_nit instead of only the first one
		// change L7(TCP/UDP) checksum
		if(iphdr->ip_p==IPPROTO_TCP){
			LINE_TRACE();
			tcp->th_dport = nit.ue_port;
			tcp->th_sum = modify_port_checksum(tcp->th_sum, iphdr->ip_dst.s_addr, nit.ue_ipv4, nit.pgw_port, nit.ue_port);
		}
		else if(iphdr->ip_p==IPPROTO_UDP){
			LINE_TRACE();
			if(b_flag!=1)
			{
				udp->uh_dport = nit.ue_port;
				udp->uh_sum = modify_port_checksum(udp->uh_sum, iphdr->ip_dst.s_addr, nit.ue_ipv4, nit.pgw_port, nit.ue_port);
			}
		}

		// change L6(IP) checksum/dst_ip
		iphdr->ip_sum = modify_checksum(iphdr->ip_sum,iphdr->ip_dst.s_addr,nit.ue_ipv4);
		iphdr->ip_dst.s_addr = nit.ue_ipv4;

		// write L5(GTP) header
		TestMsg_TRACE("\033[1;35m s1u_enb_fteid, s11_sgw_fteid=%08x, s1u_enb_fteid = %08x\033[0m, %d @ %s\n", htonl(it->second), htonl(jt->second.s1u_enb_fteid), __LINE__, __FILE__);
		// for (std::map<uint64_t,uint32_t>::iterator itt=m_out_ip_port_to_s11_sgw_fteid.begin(); itt!=m_out_ip_port_to_s11_sgw_fteid.end(); ++itt)	printf("manage_sgi_pdu - m_out_ip_port_to_s11_sgw_fteid => %016lx --> %08x\n", itt->first, htonl(itt->second));
		manage_sgi_write_gtp_header(&msg[6],iphdr->ip_len,pni->s1u_enb_fteid);

		// send out (L3/L4 information)
		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(2152);
		sin.sin_addr.s_addr = pni->enb_ipv4;
		printf("sgi_send_to_s1u_sin:%s\n",inet_ntoa(sin.sin_addr));
		
		sendto(m_s1u_soc,&msg[6],htons(iphdr->ip_len)+8,0,(sockaddr*)&sin,sizeof(sockaddr));
		RETURN;
	}
}
void spgw::run(){
	pthread_t pid;
	pthread_create(&pid,NULL,thread_send_echo_request,NULL);
	sockaddr_in src_addrin,src_addrin2;
	sockaddr_ll src_addrll;
	fd_set set;
	uint8_t msg[4000];
	int len,n,i,s1ulen;
	int laaa=0;
	uint32_t addrlen=sizeof(sockaddr);
	printf("spgw run!\n");
	
	int max_fd=(m_sgi_rx_soc>m_s1u_soc)?m_sgi_rx_soc:m_s1u_soc;
	int kk_flag=0;
	char sip_register[389];
	
	while(1){
		FD_ZERO(&set);
		FD_SET(m_sgi_rx_soc,&set);
		//FD_SET(m_s1u_if,&set);
		FD_SET(m_s1u_soc,&set);
		//FD_SET(m_sgi_sip_soc,&set);
		int n=select(max_fd+1,&set,NULL,NULL,NULL);
		if(n<0){printf("spgw select error\n");}
		else if(n){
			if(FD_ISSET(m_s1u_soc,&set)){
				len=recvfrom(m_s1u_soc,msg,3999,0,(sockaddr*)&src_addrin,&addrlen);
				printf("recvfrom s1u, from: %s, Port: %d, len:%d\n",inet_ntoa(src_addrin.sin_addr),ntohs(src_addrin.sin_port),len);
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
					/*
					printf("##################################\n");
					for(int kk=0;kk<1501;kk++){
						printf("%02x",msg[kk]);
					}
					printf("\n##################################\n");*/
					
					if(len==1508){
						kk_flag=1;
						
					}
					
					/*
					if(kk_flag!=0){
						printf("##################################\n");
						for(int kk=0;kk<len;kk++){
							printf("%02x",msg[kk]);
						}
						printf("##################################\n");
					}*/
					ip* iphdr = (ip*)&msg[GTPV1_LEN]; 
					if (iphdr->ip_p==IPPROTO_UDP && (ntohs(iphdr->ip_off)==IP_MF || ntohs(iphdr->ip_off)==IP_DF || iphdr->ip_off==0))
					{
						udphdr* udp = (udphdr*)&msg[GTPV1_LEN+sizeof(ip)];
						if (ntohs(udp->uh_dport)==5060)
						{
							char print_data[51];
							memcpy(print_data, &msg[GTPV1_LEN+sizeof(ip)+sizeof(udphdr)], 50); print_data[51]=0;
							printf("\033[1;33m recv s1u data:\n%s\033[0m\n\n", print_data);
						}
					}
					manage_s1u_pdu(msg,&src_addrin,&s1ulen);
					
					/*
					if(kk_flag!=0){
						printf("++++++++++++++++++++++++++++++++++\n");
						for(int kk=8;kk<(s1ulen+8);kk++){
							printf("%02x",msg[kk]);
						}
						printf("++++++++++++++++++++++++++++++++++\n");
					}*/
					
					len=sendto(m_sgi_tx_soc,&msg[8],s1ulen,0,(sockaddr*)&src_addrin,sizeof(src_addrin));
					if(len==1500)
						kk_flag+=1;						
					else
						kk_flag=0;
					
					
					//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					/*
					if(kk_flag==0){
						len=sendto(m_sgi_tx_soc,&msg[8],s1ulen,0,(sockaddr*)&src_addrin,sizeof(src_addrin));
					}
										
					if(len==1500||kk_flag!=0){
						
						
						printf("##################################\n");
						if(len==1500){
							for(int kk=36;kk<424;kk++){
								printf("%c",(char)msg[kk]);
								
								sip_register[kk-36] = (char)msg[kk];
								//printf("%02x",msg[kk]);
							}
						}
						printf("\n##################################\n");
						
						
						char hh[1000];
						uint8_t msgg[500];
						int llen;
						int test_soc=socket(AF_INET,SOCK_DGRAM,0);
						//sprintf(hh,"%s sip:192.168.7.120:5060 SIP/2.0\r\n","REGISTER");
						//sprintf(hh,"%s\r\n",sip_register);
						
						if(kk_flag!=0){
							llen=sendto(test_soc,sip_register,strlen(sip_register),0,(sockaddr*)&src_addrin,sizeof(src_addrin));
							printf("Test sendto : Len=%d\n",llen);
							kk_flag=0;
						}
						else{
							kk_flag=1;
						}
												
					}*/
					
					//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
					printf("sendto: %d %s, Port: %d\n",len,inet_ntoa(src_addrin.sin_addr),ntohs(src_addrin.sin_port));
					if(len<0)perror("s1u sendto");
				}
				printf("\n");
			}

				
			if(FD_ISSET(m_sgi_rx_soc,&set)){	//轉送 將SGi介面收到的封包轉送至s1u介面
				len=recvfrom(m_sgi_rx_soc,&msg[0],3999,0,(sockaddr*)&src_addrll,&addrlen);

				ip* iphdr = (ip*)&msg[14]; 
				if (iphdr->ip_p==IPPROTO_UDP && (ntohs(iphdr->ip_off)==IP_MF || ntohs(iphdr->ip_off)==IP_DF || iphdr->ip_off==0))
				{
					udphdr* udp = (udphdr*)&msg[14+sizeof(ip)];
					if (ntohs(udp->uh_sport)==5060)
					{
						char print_data[51];
						memcpy(print_data, &msg[14+sizeof(ip)+sizeof(udphdr)], 50); print_data[51]=0;
						printf("\033[1;33m recv sgi data:\n%s\033[0m\n\n", print_data);
					}
				}
				
				if(len==1514){
					printf("\nHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH\n");
					printf("AAAAAAAAAAAAAAAAAAAAA\n");
					printf("\nHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH\n");
				}
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

