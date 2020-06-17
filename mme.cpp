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

int		s1ap_socket = 0;


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
mme::run(int& fd,int socketModeone_to_many){
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
		TestMsg_TRACE("Recv S1AP packet, fd=%d, ip=%s, port=%d\n", fd, eNB_IP, ntohs(addr.sin_port)); 
		
		
		msg->msg_flags=0;
		printf("=============================================================\n");
		printf("recv buf: \n");
		for(index=0;index<nr;index++){
			printf("%02x",(unsigned char)buf[index]);
		}
		printf("\n");

		if (!memcmp(buf, "0SIP_CQI1", strlen("0SIP_CQI1")))
		{
			LINE_TRACE();
			printf("In 0SIP_CQI1\n");
			
			int i;
			traffic_flow_template_t	tft;
			uint8_t		caller_imsi[15], callee_imsi[15];
			uint32_t	caller_ip=0, callee_ip=0,caller_external_ip=0,callee_external_ip=0;
			uint16_t	caller_port=0,callee_port=0,caller_external_port=0,callee_external_port=0;
			char param[2][128];
			char *beg, *mid, *end;

			/*	
				Command = "0SIP_CQI1|CallerId:000001000100010203040506010000|CallerIP:c0a8c803|CallerPort:9c42|CalleeId:|CalleeIP:c0a800b4|CalleePort:9c40|";
				                    ^        ^                              ^
								   beg      mid                            end
			*/

			//--- analyze sip cqi1 command
			beg=(char*)buf;
			if (beg=strstr(beg,"0SIP_CQI1|"))	beg += strlen("0SIP_CQI1|")-1;
			for (i=0; i<10; i++)
			{
				if (beg)	end = strchr(beg+1,'|');
				if (end>beg)
				{
					if ((mid=strchr(beg+1,':'))>beg && mid<end)
					{
						memcpy(param[0], beg+1, mid-beg-1); param[0][mid-beg-1]=0;
						memcpy(param[1], mid+1, end-mid-1); param[1][end-mid-1]=0;
						printf("---------eRabSetup_dedicated, beg=%x, mid=%x, end=%x, param=%s:%s\n", beg, mid, end, param[0], param[1]);	
						if (!strcmp(param[0],"CallerId"))					c2u(caller_imsi, param[1], sizeof(caller_imsi));
						else if (!strcmp(param[0],"CallerIP"))				c2u((uint8_t*)&caller_ip, param[1], sizeof(caller_ip));
						else if (!strcmp(param[0],"CallerPort"))			c2u((uint8_t*)&caller_port, param[1], sizeof(caller_port));
						else if (!strcmp(param[0],"CallerExternalIP"))		c2u((uint8_t*)&caller_external_ip, param[1], sizeof(caller_external_ip));
						else if (!strcmp(param[0],"CallerExternalPort"))	c2u((uint8_t*)&caller_external_port, param[1], sizeof(caller_external_port));
						else if (!strcmp(param[0],"CalleeId"))				c2u(callee_imsi, param[1], sizeof(callee_imsi));
						else if (!strcmp(param[0],"CalleeIP"))				c2u((uint8_t*)&callee_ip, param[1], sizeof(callee_ip));
						else if (!strcmp(param[0],"CalleePort"))			c2u((uint8_t*)&callee_port, param[1], sizeof(callee_port));
						else if (!strcmp(param[0],"CalleeExternalIP"))		c2u((uint8_t*)&callee_external_ip, param[1], sizeof(callee_external_ip));
						else if (!strcmp(param[0],"CalleeExternalPort"))	c2u((uint8_t*)&callee_external_port, param[1], sizeof(callee_external_port));
						beg = end;
						LINE_TRACE();
					}
				}
				else	break;
			}
			// TestMsg_TRACE("caller_imsi:\n");
			// PrintBinary(caller_imsi,sizeof(caller_imsi));
			// TestMsg_TRACE("callee_imsi:\n");
			// PrintBinary(callee_imsi,sizeof(callee_imsi));

			TestMsg_TRACE(	"caller_imsi=%s, \ncaller_IP=0x%x, \ncaller_port=0x%x, \ncaller_external_ip=0x%x, \ncaller_external_port=0x%x\n"
							"callee_imsi=%s, \ncallee_IP=0x%x, \ncallee_port=0x%x, \ncallee_external_ip=0x%x, \ncallee_external_port=0x%x, %d @ %s\n\n", 
				GetBinaryToHexStr(caller_imsi,sizeof(caller_imsi)), 
				caller_ip, 
				caller_port,
				caller_external_ip,
				caller_external_port,
				GetBinaryToHexStr(callee_imsi,sizeof(callee_imsi)), 
				callee_ip, 
				callee_port,
				callee_external_ip,
				callee_external_port,
				__LINE__, __FILE__);

			for (int ua=0; ua<2; ua++)
			{
				uint8_t *pimsi = NULL;
				uint8_t empty_imsi[15];
				if (ua==0)	pimsi = caller_imsi;
				else	pimsi = callee_imsi;

				memset(empty_imsi, 0, sizeof(empty_imsi));
				if (!memcmp(pimsi, empty_imsi, sizeof(caller_imsi)))	
					continue;

				//--- write into tft structure
				memcpy(tft.imsi, pimsi, sizeof(tft.imsi));
				TestMsg_TRACE("tft.imsi=%s, %d @ %s\n", GetBinaryToHexStr(tft.imsi,sizeof(tft.imsi)), __LINE__, __FILE__);
				for (i=0; i<tft.filter_num; i++)
				{
					// Remote IP
					if (caller_external_ip>0 || callee_external_ip>0)
					{ 
						if ((i%2)==0)
							tft.filter[i].remote_ip = ((ua^(i%2))==0)? callee_external_ip:caller_external_ip;
						else
							tft.filter[i].remote_ip = ((ua^(i%2))==0)? callee_ip:caller_ip;
					}
					else
						tft.filter[i].remote_ip = ((ua^(i%2))==0)? callee_ip:caller_ip;
					tft.filter[i].remote_ip_mask = 0xffffffff;
					// Local Port
					if (caller_external_port>0 || callee_external_port>0)
					{
						if ((i%2)==0)
							tft.filter[i].LPort = (((ua^(i%2))==0)? caller_port:callee_port) + ((i>1)? 0x0100:0);
						else 
							tft.filter[i].LPort = (((ua^(i%2))==0)? caller_external_port:callee_external_port) + ((i>1)? 0x0100:0);
					}
					else
						tft.filter[i].LPort = (((ua^(i%2))==0)? caller_port:callee_port) + ((i>1)? 0x0100:0);
					// Real Port
					if (caller_external_port>0 || callee_external_port>0)
					{
						if ((i%2)==0)
							tft.filter[i].RPort = (((ua^(i%2))==0)? callee_external_port:caller_external_port) + ((i>1)? 0x0100:0);
						else
							tft.filter[i].RPort = (((ua^(i%2))==0)? callee_port:caller_port) + ((i>1)? 0x0100:0);
					}
					else
						tft.filter[i].RPort = (((ua^(i%2))==0)? callee_port:caller_port) + ((i>1)? 0x0100:0);
					TestMsg_TRACE("i=%d, (ua^(i%2))=%d, LPort=%d, RPort=%d\n", i, ua^(i%2), ntohs(tft.filter[i].LPort), ntohs(tft.filter[i].RPort));
				}

				LINE_TRACE();
				//--- make e-RAB EPS bearer and send out for caller
				if ((iov_len = m_s1ap->encode_ERABSetRequest_qci1(sendbuf, &tft))>0)
				{
					iov->iov_len = iov_len;
					// if(sendmsg(fd, msg,0)<0)
					printf("\033[1;31msending socket = %d\033[0m, len=%d, %d # %s\n", s1ap_socket, iov_len, __LINE__, __FILE__);
					PrintBinary((uint8_t *)iov->iov_base, iov->iov_len);
					if(sendmsg(s1ap_socket, msg,0)<0)
					{
						LINE_TRACE();
						perror("send error");
						exit(1);
					}
				}
				usleep(500000);
			}

			// respond 0SIP_CQI1
			strcpy((char*)sendbuf, "SIP_CQI10");
			if ((iov_len = strlen((char*)sendbuf))>0)
			{
				iov->iov_len = iov_len;
				// if(sendmsg(fd, msg,0)<0)
				if(sendmsg(fd, msg,0)<0)
				{
					perror("send error for SIP_CQI10");
					exit(1);
				}
			}
			continue;
		}

		NEXT_MESSAGE_STRUCT next_message;
		do{
			LINE_TRACE();
			iov_len=m_s1ap->handle_s1ap_pdu(eNB_IP,buf,sendbuf,&next_message);
			printf("\nsendlen: %d\nsendbuf: \n",iov_len);
			for(index=0;index<iov_len;index++) printf("%02x",sendbuf[index]);
			printf("\n");
			fflush(stdout);
			if(iov_len>0){
				iov->iov_len=iov_len;

				s1ap_socket = fd;
				TestMsg_TRACE("Send S1AP packet, fd=%d\n", fd); 
				if(sendmsg(fd,msg,0)<0){
					LINE_TRACE();
					perror("send error");
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

	if(socketModeone_to_many==0)
	{
		printf("\033[1;31mclose socket = %d\033[0m\n", fd);
		close(fd);
		fd = -1;
	} 
}
