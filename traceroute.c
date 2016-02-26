#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/in_systm.h>
#include"network.h"
#include<errno.h>

//#define DEBUG

ipv4 *ip;
icmp_pkt *icmp;

char sendbuf[MAXBUF];
char recvbuf[MAXBUF];

int trace_type = UDP_TRACE;

send_pkt
(int s,int ttl,short pid,struct sockaddr_in *host){
	int len;
	if(trace_type == ICMP_TRACE){	
		ip = (ipv4 *)sendbuf;
		ip->ip_v = 4;
		ip->ip_hl = 5;
		ip->tos = 0;
		ip->total_len = 18;
		ip->id = 0;		//set by the kernel
	//ip->frag_off = ;
	//ip->flags = ;
		ip->ttl = ttl;
		ip->protocol = 1;	//ICMP
		ip->chksum = 0;
	//ip->src_addr = ;
	//ip->dest_addr = ;
		icmp = (icmp_pkt *)sendbuf;
		icmp->type = ECHO_REQUEST;
		icmp->code = 0;
		icmp->chksum = 0;
		icmp->id = pid;
		icmp->seq = icmp->id + 1;
		memset(icmp->data,0x41,10);
		len = ip->total_len;
//		icmp->chksum = in_chksum((short *)icmp,len);
	}else { 
		len = 10;
		memset(sendbuf,0x41,10);
	}
	sendto(s,sendbuf,len,0,			//probably will need only send if
		(struct sockaddr *)host,	//i construct the ip hdr myself
		sizeof(*host));
}

recv_pkt
(int s,short pid,struct sockaddr_in *peer,struct sockaddr_in *sa_ptr){
	int ip_len,n,icmp_len;
	int sa_len = sizeof(*peer);
	n = recvfrom(s,recvbuf,MAXBUF,0,
		(struct sockaddr *)peer,
		&sa_len);
	ip = (ipv4 *)recvbuf;
	ip_len = ip->ip_hl << 2;
	if(ip->protocol != IPPROTO_ICMP)
		return WRONG_PROTO;
	icmp = (icmp_pkt *)((int)ip + ip_len);
	if((icmp_len = 	n - ip_len) < 8)
		return MALFORMED;
	if(icmp->type == 0x00){
		printf("received icmp echo\n");
		//if(icmp->id != pid)//this will be a logical error in udp tracing
		//	return WRONG_ID;//since the kernel sets the id
		if(icmp_len < 16)
			return INSUFF_DATA;
		if(ip->src_addr != sa_ptr->sin_addr.s_addr)
			return WRONG_HOST;
		return SUCCESS;
	}
	if(icmp->type == DEST_UNREACH){
		if(icmp->code == PORT_UNREACH)
			return SUCCESS;
		if(icmp->code == HOST_UNREACH){
			printf("host unreachable\n");
			print_pktinfo();
			printf("try pinging host first\n");
			exit(0);
		}
		if(icmp->code == NET_UNREACH){
			printf("network unreachable\n");
			print_pktinfo();
			printf("try pinging host first\n");
			exit(0);
		}
			
	}
	if(icmp->type == TIME_EXC)
		return LOW_TTL;
}

print_pktinfo
(int ttl){
	unsigned int recv_addr;
	recv_addr = ntohl(ip->src_addr);
	printf("%d  %d.%d.%d.%d\n",ttl,
		recv_addr >> 24,
		(recv_addr >> 16) & 0xff,
		(recv_addr >> 8) & 0xff,
		recv_addr & 0xff);
#ifdef DEBUG
	printf("protocol %d\n",ip->protocol);
	printf("icmp type %d code %d\n",icmp->type,icmp->code);
	printf("ip header length %d\n",ip->ip_hl);
#endif
}

main
(int argc,char *argv[]){

	int send_sock,recv_sock;
	int ttl = 1;
	int n;
	const int off = 0,on = 1;
	short pid;
	short ret_code;
	struct sockaddr_in send_sa,recv_sa;
	unsigned int recv_addr; //for printing replying host
	if(trace_type == ICMP_TRACE){
		if( (send_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) == -1){
			perror(strerror(send_sock));
			return;
		}
	}
	else{
		if( (send_sock = socket(AF_INET,SOCK_DGRAM,0)) == -1 ){ //should be UDP and receive should be icmp
			perror(strerror(send_sock));
			return;
		}
	}
	//receive socket will always be raw socket
	if( (recv_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) == -1){
		perror(strerror(recv_sock));
		return;
	}
	if(trace_type == UDP_TRACE)
		send_sa.sin_port = htons(31377);
	send_sa.sin_family = AF_INET;
	send_sa.sin_addr.s_addr = inet_addr(argv[1]);
	memset(send_sa.sin_zero,'\0',8);
	pid = getpid() & 0xffff;

	//traceroute loop
	for(EVER){
		if(trace_type == UDP_TRACE){
			if( (n = setsockopt(send_sock,IPPROTO_IP,IP_TTL,&ttl,sizeof(ttl))) == -1 ){
				printf("setting socket option block one\n");
				perror(strerror(n));
				return n;
			}
		}else{
			//setsockopt with IP_HDRINCL
		}
		send_pkt(send_sock,ttl,pid,&send_sa);
		ret_code = recv_pkt(recv_sock,pid,&recv_sa,&send_sa);
		if(ret_code == SUCCESS){
			print_pktinfo(ttl);
			break;
		}
		/*if(ret_code == WRONG_PROTO ||
		   ret_code == WRONG_HOST  ||
		   ret_code == WRONG_ID){
			printf("retcode %d\n",ret_code);
			continue;
		}*/
		if(ret_code == WRONG_HOST){
			print_pktinfo(ttl);
			ttl++;
			continue;
		}
		if(ret_code == MALFORMED ||
		   ret_code == INSUFF_DATA){
			printf("received malformed packet or insufficient data to make decision\n");
			print_pktinfo(ttl);
			printf("retrying with last ttl....\n");
			continue;
		}
		if(ret_code == LOW_TTL){
		#ifdef DEBUG
			printf("received icmp time exceeded packet\n");
		#endif
			print_pktinfo(ttl);
			ttl++;
		}
	}
}

