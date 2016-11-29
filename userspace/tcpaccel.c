#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>

#include "list.h"

#define ETHER_TYPE	0x0800
#define BUF_SIZ		1600 // > MTU 1500


#define MODE_LAN 0x01
#define MODE_WAN 0x02

#define PKT_INVALID 0x00
#define PKT_FROM_LAN 0x01
#define PKT_FROM_WAN 0x02

#define SEARCH_NOFLG 	0x00
#define SEARCH_SYN 	0x01
#define SEARCH_SYNACK 	0x02

#define MAX_PAYLOAD 2000

struct PacketTableRow {
	void* packet;
	size_t len;
	struct ether_header* eth;
	struct iphdr* ip;
	struct tcphdr* tcp;
	time_t last_send;
};

struct TcpTableRow {
	unsigned int  lan_ip_addr;
	unsigned int  wan_ip_addr;
	unsigned short lan_tcp_port;
	unsigned short wan_tcp_port;
	unsigned int lan_seq;
	unsigned int wan_seq;
	unsigned int acc_seq;
	unsigned int lan_ack_seq;
	unsigned int wan_ack_seq;
	unsigned int lan_window;
	unsigned int wan_window;
	int lan_open;
	int wan_open;
	time_t	last_operation;
	list * packetList;
};


list* tcpTableList;

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

static inline int max(int lhs, int rhs) {
    if(lhs > rhs)
        return lhs;
    else
        return rhs;
}

int sock_send_lan = 0;
int sock_send_wan = 0;
int id_lan = 0;
int id_wan = 0;

int sock_receive_lan = 0;
int sock_receive_wan = 0;


int initReceive(char* iface_name );
int initSend(char* iface_name, int *id );
int sendPacket(int send_sock,int id,void* data , size_t len );
int tcpStack(struct ether_header* eth , struct iphdr* iph,struct tcphdr* tcph, char* payload, size_t len , int pkt_from, int * forward);
void* generatePacket(   unsigned char* eth_src, unsigned char* eth_dst,
			unsigned int ip_src, unsigned int ip_dst,
			unsigned short tcp_src, unsigned short tcp_dst,
			int syn , int ack , int rst , int fin,
			unsigned int seq , unsigned int seq_ack, unsigned int window,
			char* payload , size_t payload_len , size_t *len);
struct PacketTableRow* searchPacket(struct TcpTableRow* row , unsigned int seq , int flag );
struct TcpTableRow* searchTcpTable(struct iphdr* iph , struct tcphdr* tcph);
int mainLoop(int recv_lan , int recv_wan , int send_lan, int id_lan , int send_wan , int id_wan );
void print_packet(struct ether_header* eth);

int main(int argc, char *argv[])
{
	char lanName[IFNAMSIZ+1];
	char wanName[IFNAMSIZ+1];

	if ( argc < 3 )
	{
		printf("Usage: %s LAN_INTERFACE_NAME WAN_INTERFACE_NAME\n",argv[0]);
		return -1;
	}

	if(strnlen(argv[1],IFNAMSIZ+10) > IFNAMSIZ )
	{
		printf("Error: LAN interface name too much long! =( \n");
		return -1;
	}

	if(strnlen(argv[2],IFNAMSIZ+10) > IFNAMSIZ )
	{
		printf("Error: WAN interface name too much long! =( \n");
		return -1;
	}
	strcpy(lanName,argv[1]);
	strcpy(wanName,argv[2]);

	sock_receive_lan = initReceive(lanName);
	if( sock_receive_lan <= 0 )
	{
		printf("Error: Unable to open receive LAN socket! (%d)=( \n",sock_receive_lan);
		return -1;
	}

	sock_receive_wan = initReceive(wanName);
	if( sock_receive_wan <= 0 )
	{
		printf("Error: Unable to open receive WAN  socket! =( \n");
		return -1;
	}

	sock_send_lan = initSend(lanName,&id_lan);
	if( sock_send_lan <= 0 )
	{
		printf("Error: Unable to open send LAN socket! =( \n");
		return -1;
	}

	sock_send_wan = initSend(wanName,&id_wan);
	if( sock_send_wan <= 0 )
	{
		printf("Error: Unable to open send WAN socket! =( \n");
		return -1;
	}

	tcpTableList = list_init();

	printf("Starting main loop!\n");
	mainLoop(sock_receive_lan,sock_receive_wan, sock_send_lan, id_lan , sock_send_wan, id_wan);

	close(sock_receive_lan);
	close(sock_receive_wan);

	close(sock_send_lan);
	close(sock_send_wan);
	return 0;
}


int mainLoop(int recv_lan , int recv_wan , int send_lan, int id_lan , int send_wan , int id_wan )
{
	char recv_buffer[BUF_SIZ];
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);

	struct ether_header *eth_recv = (struct ether_header *) recv_buffer;
	struct iphdr *iph_recv = (struct iphdr *) (recv_buffer + sizeof(struct ether_header));
	struct tcphdr *tcph_recv;
	char* payload;
	size_t payload_len;
	int forward;
	int pkt_from;
	int ret;
	int send_sock;
	int send_id;
	int recv_sock;
	int numbytes;
	fd_set sockets;
	struct timeval tv;


	while ( 1 )
	{
		pkt_from=PKT_INVALID;
		recv_sock = -1;

		FD_ZERO(&sockets);
		FD_SET(recv_lan,&sockets);
		FD_SET(recv_wan,&sockets);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

//		printf("Prima della select \n");
		ret = select( max(recv_lan,recv_wan) + 1 , &sockets , NULL , NULL , &tv);
//		printf("Dopo la select \n");
		//TODO set timeout, and check tcp timeout
		if ( ret == -1 )
		{
			perror("Select error");
			break;
		}

		if ( ret == 0 )
		{
//			printf("Timeout\n");
			continue;
		}
		if (FD_ISSET(recv_lan,&sockets))
		{
			recv_sock = recv_lan;
			pkt_from = PKT_FROM_LAN;
		}
		else if (FD_ISSET(recv_wan,&sockets))
		{
			recv_sock = recv_wan;
			pkt_from = PKT_FROM_WAN;
		}
		else
		{
			printf("WARNING: Invalid socket from select\n");
			continue;
		}

//		printf("prima recvfrom\n");
		numbytes = recvfrom(recv_sock, recv_buffer, BUF_SIZ, 0, (struct sockaddr*)&addr,&addr_len);
//		printf("dopo recvfrom\n");

		if ( numbytes <= 0 )
		{
			perror("Receive error");
			break;
		}
		if (addr.sll_pkttype == PACKET_OUTGOING)
		{
			continue;
		}

		print_packet(eth_recv);

		forward = 0;
		if ( eth_recv->ether_type ==  htons(ETH_P_IP) )
		{
			printf("Is IP!\n");
			if ( iph_recv->protocol == IPPROTO_TCP )
			{
				printf("Is TCP!\n");
				forward = 0;

				tcph_recv = (struct tcphdr *) ( ((void*)iph_recv) + 4*iph_recv->ihl);
				payload   = (char * ) ( ((void*)tcph_recv) + 4*tcph_recv->doff);

				payload_len = (iph_recv->tot_len) - ( (void*)iph_recv - (void*)payload);

				tcpStack(eth_recv,iph_recv,tcph_recv,payload,payload_len,pkt_from,&forward);
			}
			else
			{
				forward = 1;
			}
		}
		else
		{
			forward = 1;
		}

		if ( forward )
		{
			send_sock = -1;
			if (pkt_from == PKT_FROM_LAN)
			{
				send_sock = send_wan;
				send_id = id_wan;
			}
			else if (pkt_from == PKT_FROM_WAN)
			{
				send_sock = send_lan;
				send_id = id_lan;
			}
			else
			{
				printf("Packet from nowhere?!?!?\n");
				continue;
			}
			printf("Forwarding (out if id %d)!!\n",send_id);
			if ( sendPacket(send_sock,send_id,(void*)eth_recv,numbytes) < 0 )
			{
				printf("Error: sendPacket failed =( \n");
				break;
			}
		}
	}

	return 0;
}


int sendPacket(int send_sock,int id,void* data , size_t len )
{
	struct sockaddr_ll socket_address;

	socket_address.sll_ifindex = id;

	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;

	/* Destination MAC (Dummy) */
	socket_address.sll_addr[0] = 0x00;
	socket_address.sll_addr[1] = 0x00;
	socket_address.sll_addr[2] = 0x00;
	socket_address.sll_addr[3] = 0x00;
	socket_address.sll_addr[4] = 0x00;
	socket_address.sll_addr[5] = 0x00;

	/* Send packet */
	if (sendto(send_sock, data, len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	{
		perror("Send failed\n");
		return -1;
	}
	return 0;
}

int initReceive(char* iface_name )
{
	int sockfd;
	int sockopt;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_ll serveraddr;

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETH_P_ALL */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		perror("listener: socket");
		return -1;
	}

	printf("%s\n",iface_name);
	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, iface_name, IFNAMSIZ-1);
	if ( ioctl(sockfd, SIOCGIFFLAGS, &ifopts) < 0 )
	{
		perror("SIOCGIFFLAGS");
		close(sockfd);
		return -2;
	}
	ifopts.ifr_flags |= IFF_PROMISC;

	if ( ioctl(sockfd, SIOCSIFFLAGS, &ifopts) < 0 )
	{
		perror("SIOCSIFFLAGS");
		close(sockfd);
		return -3;
	}

	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1)
	{
		perror("setsockopt");
		close(sockfd);
		return -5;
	}

	/* bind to an interface */
	if ( ioctl(sockfd, SIOCGIFINDEX, &ifopts) < 0 )
	{
                perror("SIOCGIFINDEX");
                close(sockfd);
                return -6;
	}

	memset(&serveraddr, 0x00, sizeof(struct sockaddr_ll));

	serveraddr.sll_family = PF_PACKET;
	serveraddr.sll_protocol = htons(ETH_P_ALL);
	serveraddr.sll_halen = ETH_ALEN;
	serveraddr.sll_ifindex = ifopts.ifr_ifindex;

	if ( bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0 )
	{
		perror("bind error");
		close(sockfd);
		return -7;
	}

	return sockfd;
}


int initSend(char* iface_name , int * id)
{
	int sockfd;
	struct ifreq if_idx;

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("socket");
		close(sockfd);
		return -1;
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));

	strncpy(if_idx.ifr_name, iface_name, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		close(sockfd);
		return -2;
	}
	*id = if_idx.ifr_ifindex;
	return sockfd;
}


int cmp_tcptablerow ( void * a , void * iph_void )
{
	struct iphdr* iph = (struct iphdr*) iph_void;
	struct tcphdr *tcph = (struct tcphdr *) (iph + iph->ihl*4);
	struct TcpTableRow* row = (struct TcpTableRow*) a;

	if ( 	row->lan_ip_addr == iph->saddr &&
		row->wan_ip_addr == iph->daddr &&
		row->lan_tcp_port == tcph->dest &&
		row->wan_tcp_port == tcph->source )
	{
		return 0;
	}

	return 1;
}
struct TcpTableRow* searchTcpTable(struct iphdr* iph , struct tcphdr* tcph)
{
	return (struct TcpTableRow*) list_find(tcpTableList,iph,cmp_tcptablerow);
}

int cmp_packetflag ( void * a , void * flag_void )
{
	int flag = *((int*) flag_void);

	struct PacketTableRow* row = (struct PacketTableRow*) a;
	struct tcphdr* tcph = row->tcp;

	if ( flag == SEARCH_SYN && tcph->syn == 1 && tcph->ack == 0 ) return 0;
	if ( flag == SEARCH_SYNACK && tcph->syn == 1 && tcph->ack == 1 ) return 0;

	return 1;
}

int cmp_packetseq ( void * a , void * seq_void )
{
	int seq = *((int*) seq_void);

	struct PacketTableRow* row = (struct PacketTableRow*) a;

	if ( row->tcp->seq == seq ) return 0;

	return 1;
}


struct PacketTableRow* searchPacket(struct TcpTableRow* rowtcp , unsigned int seq , int flag )
{
	if ( flag != SEARCH_NOFLG )
	{
		return (struct PacketTableRow*) list_find(rowtcp->packetList,&flag,cmp_packetflag);
	}
	else
	{
		return (struct PacketTableRow*) list_find(rowtcp->packetList,&seq,cmp_packetseq);
	}
}


int tcpStack(struct ether_header * eth , struct iphdr* iph,struct tcphdr* tcph, char* payload, size_t len , int pkt_from, int* forward)
{
	if (pkt_from == PKT_FROM_LAN)
	{
		//New connection request
		if ( tcph->syn == 1 && tcph->ack == 0 )
		{
			printf("OK! new tcp connection!!\n");
			struct TcpTableRow* actual_row = NULL;

			//Check if Already in list
			if ( (actual_row = searchTcpTable(iph,tcph)) != NULL )
			{
				printf("Not exactly new...\n");
				if ( actual_row->lan_open == 0)
				{
					printf("But not open yet..\n");
					struct PacketTableRow* pkt_row = searchPacket(actual_row,
									0, //Seq
									SEARCH_SYNACK); //Search for SYN-ACK packet
					//Send another time
					pkt_row->last_send=time(NULL);
					actual_row->last_operation=time(NULL);
					//NOT Forward syn to remote (already done)
					*forward=0;
					//Send packet to lan host
					sendPacket(sock_send_lan,id_lan,pkt_row->packet,pkt_row->len);
				}
				else
				{
					printf("Already open?!?!?!\n");
					//Why SYN on already opened tcp?
					*forward=0;
				}
			}
			else //New connection
			{
				printf("Start the hack =) \n");

				//Generate new sequence number
				int seq = 100; //TODO RANDOM
				//Insert inside table
				struct TcpTableRow* row = (struct TcpTableRow*) malloc(sizeof(struct TcpTableRow));

//				memcpy(row->lan_eth_addr,eth->ether_shost,ETHER_ADDR_LEN);
//				memcpy(row->wan_eth_addr,eth->ether_dhost,ETHER_ADDR_LEN);
				row->lan_ip_addr = iph->saddr;
				row->wan_ip_addr = iph->daddr;
				row->lan_tcp_port = tcph->dest;
				row->wan_tcp_port = tcph->source;
				row->lan_seq = tcph->seq;
				row->wan_seq = 0;
				row->acc_seq = seq;
				row->lan_ack_seq = 0;
				row->wan_ack_seq = 0;
				row->lan_window = tcph->window;
				row->wan_window = 0;
				row->lan_open = 0;
				row->wan_open = 0;
				row->last_operation = time(NULL);
				row->packetList = list_init();

				list_append(tcpTableList,row);

				//Generate ack for lan host
				size_t len=0;
				void* pkt = generatePacket(eth->ether_dhost,eth->ether_shost,
						iph->daddr,iph->saddr,
						tcph->dest,tcph->source,
						1, //SYN FLAG
						1, //ACK FLAG
						0, //RST FLAG
						0, //FIN FLAG
						htonl(seq), //SEQ NUMBEER
						htonl(ntohl(tcph->seq) + 1), //ACK SEQ
						htonl(155), //Window TODO
						NULL, //Payload
						0, //Payload len
						&len); //Packet Len

				struct PacketTableRow* pktl = (struct PacketTableRow*) malloc(sizeof(struct PacketTableRow));
				pktl->packet = pkt;
				pktl->len = len;
				pktl->eth = (struct ether_header*) pkt;
				pktl->ip = (struct iphdr*) ( pkt + sizeof(struct ether_header));
				pktl->tcp = (struct tcphdr *) (pktl->ip + 4*pktl->ip->ihl);
				pktl->last_send = time(NULL);

				//Copy packet inside table
				list_append(row->packetList,pktl);

				//Forward syn to remote
				*forward=1;
				//Send packet to lan host
				print_packet((struct ether_header*)pkt);
				sendPacket(sock_send_lan,id_lan,pkt,len);
			}
		}
		else
		{
			printf("Not implemented yet =(\n");
		}
	}
	return 0;
}

void* generatePacket(   unsigned char* eth_src, unsigned char* eth_dst,
			unsigned int ip_src, unsigned int ip_dst,
			unsigned short tcp_src, unsigned short tcp_dst,
			int syn , int ack , int rst , int fin,
			unsigned int seq , unsigned int seq_ack, unsigned int window,
			char* payload , size_t payload_len , size_t *len)
{
	int tx_len;
	char* ret;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct tcphdr *tcph = (struct tcphdr *) ( ((void*)iph)+ sizeof(struct iphdr));
	void * p = (void*) ( ((void*)tcph) + sizeof(struct tcphdr));

	tx_len=0;
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = eth_src[0];
	eh->ether_shost[1] = eth_src[1];
	eh->ether_shost[2] = eth_src[2];
	eh->ether_shost[3] = eth_src[3];
	eh->ether_shost[4] = eth_src[4];
	eh->ether_shost[5] = eth_src[5];

	eh->ether_dhost[0] = eth_dst[0];
	eh->ether_dhost[1] = eth_dst[1];
	eh->ether_dhost[2] = eth_dst[2];
	eh->ether_dhost[3] = eth_dst[3];
	eh->ether_dhost[4] = eth_dst[4];
	eh->ether_dhost[5] = eth_dst[5];

	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);

	tx_len += sizeof(struct ether_header);

    	//Fill in the IP Header
    	iph->ihl = 5;
    	iph->version = 4;
    	iph->tos = 0;
    	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + payload_len;
    	iph->id = htonl (54321); //Id of this packet
    	iph->frag_off = 0;
    	iph->ttl = 255;
    	iph->protocol = IPPROTO_TCP;
    	iph->check = 0;      //Set to 0 before calculating checksum
    	iph->saddr = ip_src;
    	iph->daddr = ip_dst;

	tx_len += sizeof(struct iphdr);

	tcph->source = tcp_src;	//16 bit in nbp format of source port
	tcph->dest = tcp_dst;	//16 bit in nbp format of destination port
	tcph->seq = seq;		//32 bit sequence number, initially set to zero
	tcph->ack_seq = seq_ack;		//32 bit ack sequence number, depends whether ACK is set or not
	tcph->doff = 5;			//4 bits: 5 x 32-bit words on tcp header
	tcph->res1 = 0;			//4 bits: Not used
	tcph->cwr = 0;			//Congestion control mechanism
	tcph->ece = 0;			//Congestion control mechanism
	tcph->urg = 0;			//Urgent flag
	tcph->ack = ack;			//Acknownledge
	tcph->psh = 0;			//Push data immediately
	tcph->rst = rst;			//RST flag
	tcph->syn = syn;			//SYN flag
	tcph->fin = fin;			//Terminates the connection
	tcph->window = window;	//0xFFFF; //16 bit max number of databytes
	tcph->check = 0;		//16 bit check sum. Can't calculate at this point
	tcph->urg_ptr = 0;		//16 bit indicate the urgent data. Only if URG flag is set

	tx_len += sizeof(struct tcphdr);

	memcpy(p,payload,payload_len);

	tx_len += payload_len;


	struct pseudoTCPPacket pTCPPacket;
	char * pseudo_packet;

	//Now we can calculate the checksum for the TCP header
	pTCPPacket.srcAddr = ip_src;
	pTCPPacket.dstAddr = ip_dst;
	pTCPPacket.zero = 0; //8 bit always zero
	pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
	pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + payload_len); // 16 bit length of TCP header

	pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + payload_len));
 	memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + payload_len);
	memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));
	memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcph, sizeof(struct tcphdr) + payload_len);
	tcph->check= csum((unsigned short *) pseudo_packet,sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr)+payload_len);

	iph->tot_len += payload_len;
	iph->tot_len = htons(iph->tot_len);
    	iph->check =  csum ((unsigned short *) iph, sizeof(struct iphdr));

	ret = (void*) malloc(sizeof(char)*tx_len);
	memcpy(ret,sendbuf,tx_len);

	*len = tx_len;
	return ret;
}

void print_packet(struct ether_header* eh)
{
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	void * payload = NULL;
	int payload_len = 0;


	printf("Ethernet:\t ");
	printf("MAC SRC: %02x:%02x:%02x:%02x:%02x:%02x\t",eh->ether_shost[0],
							 eh->ether_shost[1],
							 eh->ether_shost[2],
							 eh->ether_shost[3],
							 eh->ether_shost[4],
							 eh->ether_shost[5]);
	printf("MAC DST: %02x:%02x:%02x:%02x:%02x:%02x\t",eh->ether_dhost[0],
							 eh->ether_dhost[1],
							 eh->ether_dhost[2],
							 eh->ether_dhost[3],
							 eh->ether_dhost[4],
							 eh->ether_dhost[5]);
	printf("ETHERTYPE: 0x%04x \n",ntohs(eh->ether_type));

	if ( eh->ether_type == htons(ETH_P_IP) )
	{
		iph = (struct iphdr *) ( ((void*)eh) + sizeof(struct ether_header));

		printf ("IPv4:\t\tIP SRC:%s\t\t",inet_ntoa(*(struct in_addr*)&iph->saddr));
		printf ("IP DST:%s\t",inet_ntoa(*(struct in_addr*)&iph->daddr));
		printf ("PROTOCOL: 0x%02x\tFF: 0x%02x\n",iph->protocol,iph->frag_off);

		if ( iph->protocol == IPPROTO_TCP )
		{
			tcph = (struct tcphdr *) ( ((void*)iph) + 4*iph->ihl);
			payload = (void*) ( ((void*)tcph) + 4*tcph->doff);
			payload_len = iph->tot_len - (((void*)iph)-payload);

			printf("TCP\t\t PORT SRC:%u\tPORT DST:%u\tSEQ:%u\tACK_SEQ:%u\tSYN:%d\tACK:%d\tRST:%d\tFIN:%d\tWINDOW:%u\n",
					ntohs(tcph->source),ntohs(tcph->dest),ntohl(tcph->seq),ntohl(tcph->ack_seq),tcph->syn,
					tcph->ack,tcph->rst,tcph->fin,ntohs(tcph->window));
		}
	}

}
