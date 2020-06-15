#ifndef __SPGW_H__
#define __SPGW_H__
#include <stdint.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <time.h>
#include <map>
#include <vector>
#include "config.h"
#include "s1ap_common.h"

#define GTPV1_LEN 8
//TODO: NAT policy:
//0~65535: no port protocol(ICMP or other), 65536~131071: first in TCP, 131072~196607: first in UDP
//					   196608~262143: second in TCP, ...
#define NAT_IPPROTO_TCP_OFFSET 65536
#define NAT_IPPROTO_UDP_OFFSET 131072
#define NAT_IPPROTO_ALL_OFFSET 65536
#define NAT_IPPROTO_GAP 131072

struct nat_information_t{
	uint32_t ue_ipv4;	// internal local ip
	uint16_t ue_port;	// internal local port
	uint32_t pgw_ipv4;	// external local ip
	uint16_t pgw_port;	// external local port

	uint32_t out_ipv4;	// remote ip
	uint16_t out_port;	// remote port

	uint8_t proto;
	time_t time_stamp;
};
struct tunnel_ctx_t{
	uint32_t s11_mme_fteid;
	uint32_t s11_sgw_fteid;
	uint32_t s1u_enb_fteid;
	uint32_t s1u_sgw_fteid;
	uint32_t enb_ipv4;
	int ebi;
	clock_t time;
	int next_sec;
	bool start;

	// std::vector<nat_information_t> m_vec_nit;	
};
class spgw{
private:
	static spgw* m_instance;

	// use s1u_sgw_fteid to get s11_sgw_fteid to get tunnel ctx in s1u while using out ip port in sgi
	std::map<uint32_t,uint32_t> m_s1u_sgw_fteid_to_s11_sgw_fteid;
	std::map<uint64_t,uint32_t> m_out_ip_port_to_s11_sgw_fteid;

	// because sgi package is much more than s11, maybe this can be changed to out_ip_port to optimize
	std::map<uint32_t,tunnel_ctx_t> m_s11_sgw_fteid_to_tunnel_ctx;
	std::map<uint64_t,nat_information_t> m_out_ip_port_to_nat_info;
	
	//Deal with the big udp packet
	std::map<short unsigned int,short unsigned int> m_s1u_udp_port;
	// std::map<u_short,uint64_t> m_s1u_udp_port;
	std::map<short unsigned int,short unsigned int> m_sgi_udp_port;

	uint32_t m_s1u_sgw_fteid;
	uint32_t m_s11_sgw_fteid;

	int m_s1u_soc;
	int m_sgi_sip_soc;

	int m_sgi_tx_soc;
	int m_sgi_rx_soc;

	std::vector<sockaddr_in> m_enb_info;

	sockaddr_in m_s1u_addr,m_sgi_addr,m_sgi_sip_addr;
public:
	static spgw* get_instance();

	spgw();
	void run();
	void send_echo_request();

	/* get functions */
	uint32_t get_s1u_addr_ipv4();
	uint32_t get_next_pdn_ipv4();
	uint32_t get_next_s11_sgw_fteid();
	uint32_t get_next_s1u_sgw_fteid();

	/* init functions */
	void init();
	void init_sgi();
	void init_s1u();

	void find_teid_by_ip(uint32_t* teid,uint32_t ip);
	void set_erab_ctx(ue_ctx_t* ue,int);

	void gtpu_write_header(uint8_t* msg,int len,uint32_t teid);

	/* Manage Requests (do Response with Parameter passed in Request) */
	void manage_create_session_request(uint32_t fteid,int bearer_id,int qCI,uint32_t* s11_sgw_fteid,uint32_t* s1u_sgw_fteid);
	void manage_end_session_request(uint32_t global_fteid);
	void manage_modify_bearer_request(uint32_t fteid,erab_setuplistctxtsures_t est);

	/* Manage input packages */
	void manage_s1u_pdu(uint8_t*,sockaddr_in*,int*);
	void manage_sgi_pdu(uint8_t*);

	/* sgi */
	void manage_sgi_write_gtp_header(uint8_t*,short,uint32_t);
};

#endif
