#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<netinet/sctp.h>
#include<arpa/inet.h>
#include"s1ap_decode.h"
#include"s1ap_encode.h"

#include "mme.h"
mme* mme::m_instance=NULL;
pthread_mutex_t mme_instance_mutex=PTHREAD_MUTEX_INITIALIZER;
mme::mme(){

}

void
mme::init(){
}

mme*
mme::get_instance(){
	pthread_mutex_lock(&mme_instance_mutex);
	if(m_instance==NULL){
		m_instance=new mme();
		m_instance->m_s1ap=s1ap::get_instance();
		m_instance->m_s1ap->init();
	}
	pthread_mutex_unlock(&mme_instance_mutex);
	return m_instance;
}

void*
mme::sctp_recv(int fd,msghdr* msg,void *buf,uint32_t *buf_len,int *nrp,uint32_t cmsglen){
	int rcv=0,cv=0;
	struct iovec iov[1];
	iov->iov_base=buf;
	iov->iov_len=*buf_len;
	msg->msg_iov=iov;
	msg->msg_iovlen=1;
	*nrp=0;
	while(1){
		msg->msg_flags=0;
		msg->msg_controllen=cmsglen;
		rcv=recvmsg(fd,msg,0);			//TODO: receive and record coming IP to distinguish who the eNB is
		if(rcv<=0){
			*nrp=cv;
			return (NULL);
		}
		cv+=rcv;
		if((msg->msg_flags & MSG_EOR)!=0){//All data delivered
			*nrp=cv;
			//printf("cv = %d\n",cv);
			return (buf);
		}
		if(*buf_len==cv){
			buf=realloc(buf,*buf_len*2);
			(*buf_len)*=2;
			if(buf==0){
				fprintf(stderr,"out of memory!");
				exit(1);
			}
		}
		iov->iov_base=(char*)buf+cv;
		iov->iov_len=*buf_len-cv;
	}
}

void
mme::run(int fd,int socketModeone_to_many){
	int nr,index,iov_len;
	struct sctp_sndrcvinfo *sri;
	struct msghdr msg[1];
	struct cmsghdr *cmsg;
	char cbuf[sizeof(*cmsg)+sizeof(*sri)];
	uint8_t *buf,sendbuf[400]={0};
	uint32_t buflen;
	struct iovec iov[1];
	uint32_t cmsglen=sizeof(*cmsg)+sizeof(*sri);

	buflen=500;
	if(!(buf=(uint8_t*)malloc(buflen))){
		printf("malloc error");
		exit(1);
	}
	memset(msg,0,sizeof(*msg));
	msg->msg_control = cbuf;
	msg->msg_controllen=cmsglen;
	msg->msg_flags=0;
	cmsg=(struct cmsghdr*) cbuf;
	sri=(struct sctp_sndrcvinfo*)(cmsg+1);
	
	while(buf=(uint8_t*)sctp_recv(fd,msg,buf,&buflen,&nr,cmsglen)){
		//printf("nr= %d\n",nr);
		if(msg->msg_flags&MSG_NOTIFICATION){
			continue;
		}
		iov->iov_base=sendbuf;
		msg->msg_iov=iov;
		msg->msg_iovlen=1;
		//printf("got %d bytes:\n",nr);
//		write(1,buf,nr);
		
		char eNB_IP[20];
		struct sockaddr_in addr;
		socklen_t addr_size = sizeof(struct sockaddr_in);
		getpeername(fd, (struct sockaddr *)&addr, &addr_size);
		strcpy(eNB_IP, inet_ntoa(addr.sin_addr));
		
		
		msg->msg_flags=0;
		printf("=============================================================\n");
		printf("recv buf: \n");
		for(index=0;index<nr;index++){
			printf("%02x",(unsigned char)buf[index]);
		}
		NEXT_MESSAGE_STRUCT next_message;
		next_message.type=-1;
		do{
			iov_len=m_s1ap->handle_s1ap_pdu(eNB_IP,buf,sendbuf,&next_message);
			printf("\nsendlen: %d\nsendbuf: \n",iov_len);
			for(index=0;index<iov_len;index++) printf("%02x",sendbuf[index]);
			printf("\n");
			fflush(stdout);
			if(iov_len>0){
				iov->iov_len=iov_len;
				if(sendmsg(fd,msg,0)<0){
					printf("send error");
					exit(1);
				}
			}
			else{		//TODO:fail
			}
		}while(next_message.type>0);
	}
	if(nr<0){
		printf("recv error");
	}

	if(socketModeone_to_many==0) close(fd);
}
