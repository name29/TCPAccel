/* Kernel Programming */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/cdev.h>
#include <net/ip.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
MODULE_AUTHOR("Emanuele Fia");
MODULE_DESCRIPTION("TCP ACCELLERATOR");
MODULE_LICENSE("BHO.0");
MODULE_VERSION("0.0.1");


#define BUFFER_MAX_PACKET_SIZE 1500;

/*
struct ethhdr {
         unsigned char   h_dest[ETH_ALEN];       // destination eth addr
         unsigned char   h_source[ETH_ALEN];     // source ether addr
        __be16          h_proto;                // packet type ID field
}

struct iphdr {
 #if defined(__LITTLE_ENDIAN_BITFIELD)
         __u8    ihl:4,
                 version:4;
 #elif defined (__BIG_ENDIAN_BITFIELD)
         __u8    version:4,
                  ihl:4;
  #else
  #error  "Please fix <asm/byteorder.h>"
  #endif
          __u8    tos;
          __be16  tot_len;
          __be16  id;
         __be16  frag_off;
         __u8    ttl;
         __u8    protocol;
         __sum16 check;
         __be32  saddr;
         __be32  daddr;
         //The options start here.
};


 struct tcphdr {
         __be16  source;
         __be16  dest;
         __be32  seq;
         __be32  ack_seq;
 #if defined(__LITTLE_ENDIAN_BITFIELD)
         __u16   res1:4,
                 doff:4,
                 fin:1,
                 syn:1,
                 rst:1,
                 psh:1,
                 ack:1,
                 urg:1,
                 ece:1,
                 cwr:1;
 #elif defined(__BIG_ENDIAN_BITFIELD)
         __u16   doff:4,
                 res1:4,
                 cwr:1,
                 ece:1,
                 urg:1,
                 ack:1,
                 psh:1,
                 rst:1,
                 syn:1,
                 fin:1;
 #else
 #error  "Adjust your <asm/byteorder.h> defines"
 #endif
         __be16  window;
         __sum16 check;
         __be16  urg_ptr;
 };
*/

/*
static unsigned int cfake_major = 0;
static struct class *cfake_class = NULL;
static struct cdev cdev;
*/


static volatile long unsigned int  atom_open_counter;

static struct packet_buffer {
	size_t size;
	size_t used;
	struct mutex mutex;
	char* data;

	char* start;
	char* end;
} pb;


int pb_init(struct packet_buffer *pb);
int pb_allocate(struct packet_buffer *pb);
int pb_deallocate(struct packet_buffer *pb);
int pb_write(struct packet_buffer *pb ,
				void *  data1, size_t len1,
				void *  data2, size_t len2,
				void *  data3, size_t len3,
				void *  data4, size_t len4 );
ssize_t pb_read_user(struct packet_buffer * pb,char* buff_userspace,size_t len);


//prototypes, else the structure initialization tat follows fail
static int dev_virtual_open(struct inode *n, struct file *fil);
static int dev_virtual_rls(struct inode *n,struct file *fil);
static ssize_t dev_virtual_read(struct file *fil, char *c, size_t len, loff_t * off);
static ssize_t dev_virtual_write(struct file *fil, const char *c, size_t len, loff_t * off);

// structure containing callbacks
static struct file_operations fops=
{
    .read=dev_virtual_read, //address of dev_read
    .open=dev_virtual_open,
    .write=dev_virtual_write,
    .release=dev_virtual_rls,
};


int new_hook_func(struct sk_buff * skb ,struct net_device * dev ,struct packet_type * pt,struct net_device * orig_dev);

static struct packet_type pkt_lan;
static struct packet_type pkt_wan;

static char * dev_name_lan = "eth1";
static char * dev_name_wan = "eth2";
static struct net_device *dev_lan;
static struct net_device *dev_wan;

#define CFAKE_DEVICE_NAME "myDev"

static int __init init_main(void)
{
	int ret;
/*
	int err = 0;
	int minor;
	dev_t devno;
	struct device * device;
	dev_t dev = 0;

	err = alloc_chrdev_region(&dev, 0, 1, CFAKE_DEVICE_NAME);
	if (err < 0) {
		printk(KERN_WARNING "[target] alloc_chrdev_region() failed\n");
		return err;
	}

	cfake_major = MAJOR(dev);

	cfake_class = class_create(THIS_MODULE, CFAKE_DEVICE_NAME);
	if (IS_ERR(cfake_class)) {
		err = PTR_ERR(cfake_class);
//		goto fail;
	}

	minor = 0;

	devno = MKDEV(cfake_major, minor);
	device = NULL;

	BUG_ON(cfake_class == NULL);

	cdev_init(&cdev, &fops);
	cdev.owner = THIS_MODULE;
	err = cdev_add(&cdev, devno, 1);
	if (err)
	{
		printk(KERN_WARNING "[target] Error %d while trying to add %s%d",
			err, CFAKE_DEVICE_NAME, minor);
		return err;
	}

	device = device_create(cfake_class, NULL, // no parent device 
		devno, NULL, // no additional data 
		CFAKE_DEVICE_NAME "%d", minor);

	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		printk(KERN_WARNING "[target] Error %d while trying to create %s%d",
			err, CFAKE_DEVICE_NAME, minor);
		cdev_del(&cdev);
		return err;
	}
*/

	set_bit(0,&atom_open_counter);

	pb_init(&pb);

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

	ret = register_chrdev(89,"myDev",&fops); //register with major number

	if(ret<0)
	{
		printk(KERN_ALERT "Device registration failed.. \n");
	}
    	else
	{
		printk(KERN_ALERT "device registered \n");
	}

	printk( KERN_ALERT "TCPAccel successfull loaded! Thank you GOD!\n");
	return 0;
}

static void __exit cleanup_main(void)
{
/*
	int minor;
	minor = 0;


       	dev_remove_pack(&pkt_lan);
       	dev_remove_pack(&pkt_wan);

	device_destroy(cfake_class, MKDEV(cfake_major, minor));

	if (cfake_class)
		class_destroy(cfake_class);

	unregister_chrdev_region(MKDEV(cfake_major, 0),0);
*/
	unregister_chrdev(89,"myDev");

	printk(KERN_ALERT "module exit");
}

module_init(init_main);
module_exit(cleanup_main);

int new_hook_func(struct sk_buff * skb ,struct net_device * dv ,struct packet_type * pt,struct net_device * dv2)
{
	struct iphdr *ip;
       	struct ethhdr *eth;
       	struct tcphdr *tcp;

	int ret;
	int show_warning;

	show_warning=0;

	eth  = eth_hdr(skb);
	if(skb->pkt_type != PACKET_OUTGOING)
	{
		//out packet
		struct sk_buff *my_skb = 0;
	        my_skb = skb_copy_expand(skb, 16, 16, GFP_ATOMIC);
        	skb_push(my_skb, ETH_HLEN);
        	my_skb->pkt_type = PACKET_OUTGOING;

		if ( dv == dev_wan ) my_skb->dev = dev_lan;
		else if ( dv == dev_lan ) my_skb->dev = dev_wan;

		if ( ntohs(eth->h_proto) == 2048 )
		{
			ip = (struct iphdr*)skb_network_header(skb);

			if(ip->version == 4 && ip->protocol == IPPROTO_TCP)
			{
				tcp = (struct tcphdr *) skb_transport_header(skb);

				if ( test_bit(1,&atom_open_counter) == 1 )
				{
					size_t eth_s = sizeof(struct ethhdr);
					size_t ip_s = ip->ihl*4;
					size_t tcp_s = tcp->doff*4;
					size_t payload_s = (size_t) (skb->data-skb->tail);

					if ( pb_write(&pb,
							eth,eth_s,
							ip,ip_s,
							tcp,tcp_s,
							skb->data,payload_s))
					{
						printk(KERN_ALERT "Unable to save packet! BUFFER FULL! This packet is lost! (consider adjust buffer size)\n");
					}
				}

				goto tcpaccel_free;
			}
		}

        	ret = dev_queue_xmit(my_skb);

tcpaccel_free:
		kfree_skb(my_skb);
	}
	kfree_skb(skb);
	return NET_RX_DROP;
}

//called when "open" system call is done on the device file
static int dev_virtual_open(struct inode *inod, struct file *fil)
{
	if ( test_and_set_bit(1, &atom_open_counter) != 0 )
	{
		printk(KERN_ALERT "EBBChar: Device in use by another process");
      		return -EBUSY;
	}

	if ( pb_allocate(&pb) != 0 )
	{
		printk(KERN_ALERT "Unable to allocate space for internal buffer inside the Kernel! =(\n");

		set_bit(0,&atom_open_counter);

		return -EBUSY;
	}

	printk(KERN_ALERT "Someone open the devfile =) \n");

	return 0;
}

// called when 'read' system call
static ssize_t dev_virtual_read(struct file *fil, char *buff_userspace, size_t len, loff_t * off)
{
	return pb_read_user(&pb,buff_userspace,len);
}

//called when 'write' is called on device file
static ssize_t dev_virtual_write(struct file *fil, const char *buff, size_t len, loff_t * off)
{
	return -1;
}

//called when 'close' system call
static int dev_virtual_rls(struct inode *inod, struct file *fil)
{
	set_bit(0,&atom_open_counter);

	return 0;
}



int pb_deallocate(struct packet_buffer *pb)
{
	mutex_lock(&(pb->mutex));

	kfree(pb->data);

	pb->size=0;
	pb->used=0;
	pb->data=NULL;
	pb->start=NULL;
	pb->end=NULL;

	mutex_unlock(&(pb->mutex));

	return 0;
}

int pb_allocate(struct packet_buffer *pb)
{
	mutex_lock(&(pb->mutex));

	pb->used = 0;
	pb->size = 0;
	pb->size += 18; //Max Ethernet 	HEADER
	pb->size += 60; //Max IP  	HEADER
	pb->size += 60; //Max TCP		HEADER
	pb->size += 1470; //Max Payload (MTU 1500)

	pb->size *= BUFFER_MAX_PACKET_SIZE;

	pb->start = pb->end = pb->data = kmalloc( pb->size , GFP_KERNEL);

	if ( pb->data == NULL )
	{
		pb->used = 0;
		pb->size = 0;

		mutex_unlock(&(pb->mutex));

		return -1;
	}

	mutex_unlock(&(pb->mutex));

	return 0;
}

int pb_init(struct packet_buffer *pb)
{
	pb->used = 0;
	pb->size = 0;
	pb->start = 0;
	pb->end = 0;
	pb->data = NULL;

	mutex_init(&(pb->mutex));

	return 0;
}

int pb_write_internal(struct packet_buffer *pb ,
				void *  data, size_t len)
{
	size_t actual_offset;
	size_t avail;

	//Ok there are space inside the circular buffer

	actual_offset = pb->end - pb->data;

	if ( pb->size - actual_offset > len )
	{
		//rewind not needed
		memcpy(pb->end,data,len);

		pb->end += len;
		pb->used += len;
	}
	else
	{
		//Oh no! rewind needed
		avail = (pb->size - actual_offset);
		memcpy(pb->end,data,avail);

		pb->end = pb->data; //rewind

		memcpy(pb->end,data+avail,len-avail);

		pb->end += avail;
		pb->used += len;
	}

	return 0;
}

int pb_write(struct packet_buffer *pb ,
				void *  data1, size_t len1,
				void *  data2, size_t len2,
				void *  data3, size_t len3,
				void *  data4, size_t len4 )
{
	int ret;
	int len;

	len= len1 + len2 + len3 + len4;
	ret = 0;

	mutex_lock(&(pb->mutex));
	if ( len <= pb->size - pb->used )
	{
		//Ok there are space inside the circular buffer
		pb_write_internal(pb,data1,len1);
		pb_write_internal(pb,data2,len2);
		pb_write_internal(pb,data3,len3);
		pb_write_internal(pb,data4,len4);
	}
	else
	{
		ret=1;
	}

	mutex_unlock(&(pb->mutex));

	return ret;
}


ssize_t pb_read_user(struct packet_buffer * pb,char* buff_userspace,size_t len)
{
	int to_read;
	int not_writed;
	int avail;
	size_t actual_offset;

	mutex_lock(&(pb->mutex));

	to_read = 0;
	if ( pb->used > 0 )
	{

		if ( pb->used < len ) to_read = pb->used;
		else to_read = len;

		actual_offset = pb->start - pb->data;

		if ( pb->size - actual_offset > to_read )
		{
			//rewind not needed
			not_writed = copy_to_user(buff_userspace,pb->start,to_read);

			pb->start += (to_read - not_writed);
			pb->used -= (to_read - not_writed);
		}
		else
		{
			//Oh no! rewind needed
			avail = (pb->size - actual_offset);
			not_writed  = copy_to_user(buff_userspace,pb->start,avail);

			pb->used -= (avail - not_writed);

			if ( not_writed == 0 )
			{
				pb->start = pb->data; //rewind

				not_writed = copy_to_user(buff_userspace,pb->start,to_read-avail);

				pb->start += (to_read - avail - not_writed);
				pb->used  -= (to_read - avail - not_writed);
			}
			else
			{
				pb->start -= (avail  - not_writed);

				not_writed += (to_read-avail);
			}
		}
	}
	mutex_unlock(&(pb->mutex));

	return (to_read - not_writed);
}
