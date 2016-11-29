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

#define ETHER_TYPE	0x0800
#define BUF_SIZ		1600 // > MTU 1500


//TODO REMOVE
#define MY_DEST_MAC0 0x00
#define MY_DEST_MAC1 0x00
#define MY_DEST_MAC2 0x00
#define MY_DEST_MAC3 0x00
#define MY_DEST_MAC4 0x00
#define MY_DEST_MAC5 0x00

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

#define MODE_LAN 0x01
#define MODE_WAN 0x02


int initReceive(char* iface_name );
int initSend(char* iface_name, int *id );
int mainLoop(int recv_lan , int recv_wan , int send_lan, int id_lan , int send_wan , int id_wan );

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

	int sock_send_lan = 0;
	int sock_send_wan = 0;
	int id_lan = 0;
	int id_wan = 0;

	int sock_receive_lan = 0;
	int sock_receive_wan = 0;

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

	printf("Starting main loop!\n");
	mainLoop(sock_receive_lan,sock_receive_wan, sock_send_lan, id_lan , sock_send_wan, id_wan);

	close(sock_receive_lan);
	close(sock_receive_wan);

	close(sock_send_lan);
	close(sock_send_wan);
	return 0;
}


#define PKT_INVALID 0x00
#define PKT_FROM_LAN 0x01
#define PKT_FROM_WAN 0x02

int mainLoop(int recv_lan , int recv_wan , int send_lan, int id_lan , int send_wan , int id_wan )
{
	char recv_buffer[BUF_SIZ];
	struct ether_header *eth_recv = (struct ether_header *) recv_buffer;
	struct iphdr *iph_recv = (struct iphdr *) (recv_buffer + sizeof(struct ether_header));
	struct tcphdr *tcph_recv;
	char* data;
	int forward;
	int pkt_from;
	int ret;
	int send_sock;
	int send_id;
	int recv_sock;
	int numbytes;
	fd_set sockets;
	fd_set readsocks;

	FD_ZERO(&sockets);
	FD_SET(recv_lan,&sockets);
	FD_SET(recv_wan,&sockets);

	while ( 1 )
	{
		pkt_from=PKT_INVALID;
		recv_sock = -1;
		readsocks = sockets;
		ret = select( 2 + 1 , &readsocks , NULL , NULL , NULL);

		if ( ret == -1 )
		{
			perror("Select error");
			break;
		}

		if (FD_ISSET(recv_lan,&readsocks))
		{
			recv_sock = recv_lan;
			pkt_from = PKT_FROM_LAN;
		}
		else if (FD_ISSET(recv_wan,&readsocks))
		{
			recv_sock = recv_wan;
			pkt_from = PKT_FROM_WAN;
		}
		else
		{
			printf("WARNING: Invalid socket from select\n");
			continue;
		}

		numbytes = recvfrom(recv_sock, recv_buffer, BUF_SIZ, 0, NULL, NULL);

		if ( numbytes <= 0 )
		{
			perror("Receive error");
			break;
		}

		forward = 0;
		if ( eth_recv->ether_type ==  htons(ETH_P_IP) )
		{
			if ( iph_recv->protocol == IPPROTO_TCP )
			{
				tcph_recv = (struct tcphdr *) (recv_buffer + 4*iph_recv->ihl);
				payload   = (char * ) (tcph_recv + 4*tcp_recv->doff);
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
			if (PKT_FROM_LAN)
			{
				send_sock = send_lan;
				send_id = id_lan;
			}
			if (PKT_FROM_WAN)
			{
				send_sock = send_wan;
				send_id = id_wan;
			}

			if ( sendPacket(send_sock,send_id,eth_recv,numbytes) < 0 )
			{
				printf("Error: sendPacket failed =( \n");
				break;
			}
		}
	}

	return 0;
}


int sendPacket(int send_sock,int id,char* data , int len )
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
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
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
		return -4;
	}

	/* bind to an interface */
	if ( ioctl(sockfd, SIOCGIFINDEX, &ifopts) < 0 )
	{
                perror("SIOCGIFINDEX");
                close(sockfd);
                return -5;
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
		return -6;
	}

	return sockfd;
}


int initSend(char* iface_name , int * id)
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;

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

	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));

	strncpy(if_mac.ifr_name, iface_name, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	{
		perror("SIOCGIFHWADDR");
		close(sockfd);
		return -3;
	}

	return sockfd;
}


int foo()
{
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct tcphdr *tcph = (struct tcphdr *) (sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr));

	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);

	tx_len += sizeof(struct ether_header);

    	//Fill in the IP Header
    	iph->ihl = 5;
    	iph->version = 4;
    	iph->tos = 0;
    	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
    	iph->id = htonl (54321); //Id of this packet
    	iph->frag_off = 0;
    	iph->ttl = 255;
    	iph->protocol = IPPROTO_TCP;
    	iph->check = 0;      //Set to 0 before calculating checksum
    	iph->saddr = inet_addr ("192.168.1.1");
    	iph->daddr = inet_addr ("192.168.1.20");

	tx_len += sizeof(struct iphdr);

	tcph->source = htons(123);	//16 bit in nbp format of source port
	tcph->dest = htons(321);	//16 bit in nbp format of destination port
	tcph->seq = 0x0;		//32 bit sequence number, initially set to zero
	tcph->ack_seq = 0x0;		//32 bit ack sequence number, depends whether ACK is set or not
	tcph->doff = 5;			//4 bits: 5 x 32-bit words on tcp header
	tcph->res1 = 0;			//4 bits: Not used
	tcph->cwr = 0;			//Congestion control mechanism
	tcph->ece = 0;			//Congestion control mechanism
	tcph->urg = 0;			//Urgent flag
	tcph->ack = 0;			//Acknownledge
	tcph->psh = 0;			//Push data immediately
	tcph->rst = 0;			//RST flag
	tcph->syn = 1;			//SYN flag
	tcph->fin = 0;			//Terminates the connection
	tcph->window = htons(155);	//0xFFFF; //16 bit max number of databytes
	tcph->check = 0;		//16 bit check sum. Can't calculate at this point
	tcph->urg_ptr = 0;		//16 bit indicate the urgent data. Only if URG flag is set

	tx_len += sizeof(struct tcphdr);

	int payload_len = tx_len;

	sendbuf[tx_len++]='T';
	sendbuf[tx_len++]='h';
	sendbuf[tx_len++]='i';
	sendbuf[tx_len++]='s';
	sendbuf[tx_len++]='-';
	sendbuf[tx_len++]='i';
	sendbuf[tx_len++]='s';
	sendbuf[tx_len++]='-';
	sendbuf[tx_len++]='a';
	sendbuf[tx_len++]='-';
	sendbuf[tx_len++]='p';
	sendbuf[tx_len++]='a';
	sendbuf[tx_len++]='y';
	sendbuf[tx_len++]='l';
	sendbuf[tx_len++]='o';
	sendbuf[tx_len++]='a';
	sendbuf[tx_len++]='d';
	sendbuf[tx_len++]='!';

	payload_len = tx_len - payload_len;
	printf("%d\n",payload_len);

	struct pseudoTCPPacket pTCPPacket;
	char * pseudo_packet;

	//Now we can calculate the checksum for the TCP header
	pTCPPacket.srcAddr = inet_addr("192.168.1.1"); //32 bit format of source address
	pTCPPacket.dstAddr = inet_addr("192.168.1.20"); //32 bit format of source address
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

	printf("DONE\n");
	return 0;
}
