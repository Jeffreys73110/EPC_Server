#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>


sockaddr_in Addr;

int main(){
	printf("hello\n");
	len=sendto(m_s1u_soc,msg,14,0,(sockaddr*)&Addr,sizeof(Addr));
}



