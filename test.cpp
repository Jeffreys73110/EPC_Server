#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<netinet/sctp.h>
#include<arpa/inet.h>
#include<pthread.h>
#include "config.h"
#include"s1ap_decode.h"
#include"s1ap_encode.h"
#include"mme.h"
#include <unistd.h>
#include "Func.h"

#define BUFLEN 100
static void set_sctp_event(struct sctp_event_subscribe* ses){
	ses->sctp_data_io_event=1;
	ses->sctp_shutdown_event=1;
/*	ses->sctp_association_event=1;
	ses->sctp_address_event=1;
	ses->sctp_send_failure_event=1;
	ses->sctp_peer_error_event=1;
	ses->sctp_partial_delivery_event=1;
	ses->sctp_adaptation_layer_event=1;
	ses->sctp_authentication_event=1;
*/}

static void server_response(int& fd,int socketModeone_to_many){
	mme* mme=mme::get_instance();
	mme->init();
	mme->run(fd,socketModeone_to_many);
}
void* spgw_start(void* arg){
	spgw* spgw=spgw::get_instance();
	spgw->init();
	spgw->run();
	return NULL;
}
void* mme_start(void* arg){
	while(1){//不停收下一則訊息
	if (*(int*)arg<0)	break;

		struct sctp_event_subscribe ses;
		set_sctp_event(&ses);
		if(setsockopt(*(int*)arg,IPPROTO_SCTP,
		    SCTP_EVENTS,&ses,sizeof(ses))!=0) {
			printf("set socket error\n");
			exit(1);
		}
		server_response(*(int*)arg,0);
	}
}
int socket_start(char* IP,int PORT_NUM){
	sockaddr_in sin;
	sin.sin_family=AF_INET;
	sin.sin_port=htons(PORT_NUM);
	sin.sin_addr.s_addr=inet_addr(IP);
	int soc;
	if((soc=socket(AF_INET,SOCK_STREAM,IPPROTO_SCTP))<0){
		printf("socket error\n");
		return -1;
	}
	if(bind(soc,(sockaddr*)&sin,sizeof(sin))<0){
		printf("bind error\n");
		return -1;
	}
	listen(soc,10);
	return soc;
}
int main(){
	
	char LOCAL_IP_ADDRESS[64]=MME_IP;
	int soc=socket_start(LOCAL_IP_ADDRESS,36412);
	pthread_t tid,tid1;
	//pid_t pid;
	pthread_create(&tid,NULL,spgw_start,NULL);
	char clientip[20];

	LINE_TRACE();
	
	while(1){//避免socket建立失敗造成直接停止
		sockaddr_in accsin;
		unsigned int len=sizeof(sockaddr);
		int accsoc=accept(soc,(sockaddr*)&accsin,&len);
		printf("\033[1;31maccept socket = %d\033[0m\n", accsoc);
		printf("make pthread\n");		
		pthread_create(&tid1,NULL,mme_start,&accsoc);
		sleep(1);
	}
}