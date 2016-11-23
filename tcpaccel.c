/* Kernel Programming */
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tcp.h>

MODULE_AUTHOR("Emanuele Fia");
MODULE_DESCRIPTION("TCP ACCELLERATOR");
MODULE_LICENSE("BHO 2.0");
MODULE_VERSION("0.0.1");

/*
#include <linux/module.h>  // Needed by all modules 
#include <linux/kernel.h>  // Needed for KERN_ALERT
#include <linux/init.h>     // Needed for the macros
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <asm-generic/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_defs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/ip.h>

*/

/*
static struct nf_hook_ops nfin;

static unsigned int hook_func_in(unsigned int hooknum,
            struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out,
                            int (*okfn)(struct sk_buff *))
{
    struct ethhdr *eth;
    struct iphdr *ip_header;

    struct tcphdr *tcp;

    eth = (struct ethhdr*)skb_mac_header(skb);
    ip_header = (struct iphdr *)skb_network_header(skb);

    if (ip_header->protocol != 6)
	return NF_ACCEPT;

    tcp = (struct tcphdr*)((__u32 *)ip_header+ip_header->ihl);

    printk("src mac %pM, dst mac %pM\n", eth->h_source, eth->h_dest);
    printk("src IP addr:=%pi4\n", ip_header->saddr);
    return NF_ACCEPT;
}
*/

//int new_hook_func(struct sk_buff *skb, struct device *dv, struct packet_type *pt);
int new_hook_func(struct sk_buff * skb ,struct net_device * dev ,struct packet_type * pt,struct net_device * orig_dev);

static struct packet_type pkt_lan;
static struct packet_type pkt_wan;

char * dev_name_lan = "eth1";
char * dev_name_wan = "eth2";
struct net_device *dev_lan;
struct net_device *dev_wan;


static int __init init_main(void)
{
/*
    nfin.hook     = hook_func_in;
    nfin.hooknum  = NF_INET_PRE_ROUTING;
    nfin.pf       = PF_INET;
    nfin.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfin);
*/
/*
struct packet_type {
        __be16                  type;   // This is really htons(ether_type). 
        struct net_device       *dev;   // NULL is wildcarded here          
        int                     (*func) (struct sk_buff *,
                                         struct net_device *,
                                         struct packet_type *,
                                         struct net_device *);
        bool                    (*id_match)(struct packet_type *ptype,
                                            struct sock *sk);
        void                    *af_packet_priv;
        struct list_head        list;
}
*/
	dev_lan = dev_get_by_name(&init_net, dev_name_lan);
	pkt_lan.type = htons(ETH_P_ALL);
	pkt_lan.func = new_hook_func;
	pkt_lan.dev = dev_lan;
	dev_add_pack(&pkt_lan);

	dev_wan = dev_get_by_name(&init_net, dev_name_wan);
	pkt_wan.type = htons(ETH_P_ALL);
	pkt_wan.func = new_hook_func;
	pkt_wan.dev = dev_wan;
	dev_add_pack(&pkt_wan);

	printk( KERN_ALERT "TCPAccel successfull loaded! Thank you GOD!\n");
	return 0;
}

static void __exit cleanup_main(void)
{
/*
    nf_unregister_hook(&nfin);
*/
       	dev_remove_pack(&pkt_lan);
       	dev_remove_pack(&pkt_wan);
	printk(KERN_ALERT "module exit");
}

module_init(init_main);
module_exit(cleanup_main);

int new_hook_func(struct sk_buff * skb ,struct net_device * dv ,struct packet_type * pt,struct net_device * dv2)
//int new_hook_func(struct sk_buff *skb, struct device *dv, struct packet_type *pt)
{
	struct iphdr *ip;
       	struct ethhdr *eth;
       	struct tcphdr *tcp;

    	struct sk_buff *newskb;
    	struct iphdr *newip;
    	struct tcphdr *newtcp;
	int newlen;
	int newsend;
	struct net_device* exit_dev;
	int tmp;
	int ret;

	newsend=0;
	eth  = eth_hdr(skb);
	if(skb->pkt_type != PACKET_OUTGOING)
	{
        	struct sk_buff *my_skb = 0;

        	//copy incoming skb
	        my_skb = skb_copy_expand(skb, 16, 16, GFP_ATOMIC);

        	//push ethernet layer to skb
        	skb_push(my_skb, ETH_HLEN);

        	my_skb->pkt_type = PACKET_OUTGOING;

//		printk( KERN_ALERT "TCPAccel new packet received from %pM to %pM (proto %hu)!\n",&(eth->h_source),&(eth->h_dest),ntohs(eth->h_proto));

		if ( dv == dev_wan )
		{
			my_skb->dev = dev_lan;
		}
		else if ( dv == dev_lan )
		{
			my_skb->dev = dev_wan;
		}

		if ( ntohs(eth->h_proto) == 2048 )
		{
			ip = (struct iphdr*)skb_network_header(my_skb);
			tmp = ip->protocol;
//			printk( KERN_ALERT "TCPAccel new packet received from %pI4 to %pI4 (proto %d)!\n",&(ip->saddr),&(ip->daddr),tmp);

			if(ip->version == 4 && ip->protocol == IPPROTO_TCP)
			{
				tcp = (struct tcphdr *) skb_transport_header(my_skb);

				newlen = ETH_FRAME_LEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + 0x00;
				newskb = alloc_skb(newlen, GFP_KERNEL);

    				if (skb_linearize(newskb) < 0)
				{
					printk( KERN_ALERT "TCPAccel linearize error =(\n");
					return NF_DROP;
				}

    				skb_reserve(newskb, newlen);


				newskb->csum = 0;

				skb_push(newskb, sizeof(struct tcphdr));
				skb_reset_transport_header(newskb);

				newtcp = (struct tcphdr *) skb_transport_header(newskb);
				//newtcp = (void *)skb_put(newskb, sizeof(struct tcphdr));
				//skb_put re-sets the tail for udphdr
				newtcp->source = tcp->dest;
				newtcp->dest   = tcp->source;
				newtcp->check = 0;

				if ( dv == dev_wan )
				{
					if ( tcp->syn && ! tcp->ack )
					{
					}
					else if ( tcp->syn && tcp->ack )
					{

					}
					else if ( tcp->ack )
					{
						printk(KERN_ALERT "it's my time!!!\n");
						//Ignore flag e ignore window
						newtcp->seq = 0;
						newtcp->ack_seq = tcp->seq + 1;
						newtcp->res1 = 0;
						newtcp->doff = 0;
						newtcp->fin = 0;
						newtcp->syn = 0;
						newtcp->rst = 0;
						newtcp->psh = 0;
						newtcp->ack = 1;
						newtcp->urg = 0;
						newtcp->ece = 0;
						newtcp->cwr = 0;
						newtcp->window = 0;
						newtcp->check = 0;
						newtcp->urg_ptr = 0;

						newsend=1;
						exit_dev=dev_lan;
					}
					//Gestisco ack se presente
					//Se ci sono altri dati gli invio al destinatario
				}
				else if ( dv == dev_lan )
				{
					if ( tcp->syn && ! tcp->ack )
					{

					}
					else if ( tcp->syn && tcp->ack )
					{

					}

					//Gestisco tutto
				}
				if (newsend)
				{
					newskb->csum = csum_partial ((char*) newtcp, sizeof(struct udphdr),newskb->csum);
					newtcp->check = csum_tcpudp_magic(newtcp->source,newtcp->dest,0,IPPROTO_TCP,newskb->csum);

					if (newtcp->check == 0)
					{
						printk(KERN_ALERT "check 0!!!!!\n");
					}

					skb_push(newskb,sizeof(struct iphdr));
					skb_reset_network_header(newskb);
					newip = (struct iphdr*)skb_network_header(newskb);

    					//newip = (void *)skb_put(newskb, sizeof(struct iphdr*));
    					//skb_put sets the tail for iphdr
    					newip->version  = IPVERSION;
    					newip->ihl      = sizeof(struct iphdr) / 4;
    					newip->tos      = 0;
					newip->tot_len  = htons(newskb->len);
    					newip->id       = 0;
    					newip->frag_off = 0;
	//    				newip->frag_off = htons(IP_DF);
					newip->ttl	= 255;
    					newip->protocol = IPPROTO_TCP;
    					newip->check    = 0;
    					newip->saddr    = ip->daddr; //SWAP
    					newip->daddr    = ip->saddr; //SWAP

					ip_send_check(newip);
					dev_hard_header(newskb, exit_dev, ETH_P_IP, eth->h_dest, eth->h_source, exit_dev->addr_len);

			        	ret = dev_queue_xmit(newskb);
					printk(KERN_ALERT "dev_queue_xmit (fake ACK) returned %d\n", ret);
				}
    				kfree_skb(newskb);
			}
		}
        	ret = dev_queue_xmit(my_skb);
//		printk(KERN_ALERT "dev_queue_xmit returned %d\n", ret);

	        //drop all incoming packets
		//kfree_skb(my_skb);
		//kfree_skb(skb);

	}
	return NET_RX_DROP;
}

