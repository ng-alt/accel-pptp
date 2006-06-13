/*
 *  Point to Point Tunneling Protocol for Linux
 *
 *	Authors: Kozlov D. (xeb@mail.ru)
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 */

#include <linux/string.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ppp_channel.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <linux/notifier.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/version.h>

#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>

#include <asm/uaccess.h>

#include "pptp_msg.h"

#define PPTP_MAJOR	245

#define PPTP_DRIVER_VERSION "0.6"
#define PPTP_PROTO 47

MODULE_DESCRIPTION("Point-to-Point Tunneling Protocol for Linux");
MODULE_AUTHOR("Kozlov D. (xeb@mail.ru)");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CHARDEV_MAJOR(PPTP_MAJOR);
MODULE_ALIAS("/dev/pptp");

static int log_level=0;
static struct proc_dir_entry* proc_dir;

static int min_window=5;
static int max_window=100;
module_param(min_window,int,5);
MODULE_PARM_DESC(min_window,"Minimum sliding window size (default=3)");
module_param(max_window,int,100);
MODULE_PARM_DESC(max_window,"Maximum sliding window size (default=100)");
module_param(log_level,int,0);

#define HASH_SIZE  16
#define HASH(addr) ((addr^(addr>>4))&0xF)
static DEFINE_RWLOCK(chan_lock);
static struct list_head chans[HASH_SIZE];


typedef struct pack_track {
  uint32_t seq;       // seq no of this tracked packet
  uint64_t time;      // time when this tracked packet was sent (in usecs)
} pack_track_t;

typedef struct gre_stats {
  /* statistics for GRE receive */

  uint32_t rx_accepted;  // data packet was passed to pppd
  uint32_t rx_lost;      // data packet did not arrive before timeout
  uint32_t rx_underwin;  // data packet was under window (arrived too late
                         // or duplicate packet)
  uint32_t rx_overwin;   // data packet was over window
                         // (too many packets lost?)
  uint32_t rx_buffered;  // data packet arrived earlier than expected,
                         // packet(s) before it were lost or reordered
  uint32_t rx_errors;    // OS error on receive
  uint32_t rx_truncated; // truncated packet
  uint32_t rx_invalid;   // wrong protocol or invalid flags
  uint32_t rx_acks;      // acknowledgement only

  /* statistics for GRE transmit */

  uint32_t tx_sent;      // data packet write() to GRE socket succeeded
  uint32_t tx_failed;    // data packet write() to GRE socket returned error
  uint32_t tx_acks;      // sent packet with just ACK

  /* statistics for packet tracking, for RTT calculation */

  pack_track_t pt;       // last data packet seq/time
  int rtt;               // estimated round-trip time in us

} gre_stats_t;

struct pptp_conn_t {
	__u16 call_id;
	__u16 peer_call_id;
	struct in_addr sin_addr;
	struct in_addr loc_addr;
	__u32 timeout;
	__u32 window;
};

struct pptp_chan_t {
	struct list_head entry;
	__u16 call_id;
	__u16 peer_call_id;
	struct in_addr dst_addr;
	struct in_addr src_addr;
	struct ppp_channel ppp_chan;
	int mru;
  int flags;
  int timeout;
 	int window;

	gre_stats_t stats;
	u_int32_t ack_sent, ack_recv;
	u_int32_t seq_sent, seq_recv;
	int pause;

	rwlock_t skb_buf_lock;
	struct sk_buff_head skb_buf;
	struct timer_list ack_timer; //send ack timer
	struct timer_list buf_timer; //check buffered packets timer
};


static int process_outgoing_skb(struct ppp_channel *chan, struct sk_buff *skb);
static int process_incoming_skb(struct pptp_chan_t *ch,struct sk_buff *skb,int new);
static int ppp_ioctl(struct ppp_channel *chan, unsigned int cmd, unsigned long arg);
static int read_proc(char *page, char **start, off_t off,int count, int *eof, void *data);

static struct ppp_channel_ops pptp_chan_ops= {
	process_outgoing_skb,
	ppp_ioctl
};

static struct pptp_chan_t* lookup_chan(u16 call_id)
{
	struct pptp_chan_t *ch;
	struct list_head *h=chans+HASH(call_id);
	list_for_each_entry(ch,h,entry){
		if (ch->call_id==call_id) return ch;
	}
	return NULL;
}

static int process_outgoing_skb(struct ppp_channel *chan, struct sk_buff *skb)
{
	struct pptp_chan_t *ch=(struct pptp_chan_t *)chan->private;
	struct pptp_gre_header *hdr;
  unsigned int header_len=sizeof(*hdr);
  int len=skb?skb->len:0;
	int err=0;

	struct rtable *rt;     			/* Route to the other host */
	struct net_device *tdev;			/* Device to other host */
	struct iphdr  *iph;			/* Our new IP header */
	int    max_headroom;			/* The extra header space needed */


	if (skb && ch->stats.pt.seq-ch->ack_recv>ch->window){
		ch->pause=1;
		return 0;
	}

	{
		struct flowi fl = { .oif = 0,
				    .nl_u = { .ip4_u =
					      { .daddr = ch->dst_addr.s_addr,
						.saddr = ch->src_addr.s_addr,
						.tos = RT_TOS(0) } },
				    .proto = IPPROTO_GRE };
		if ((err=ip_route_output_key(&rt, &fl))) {
			goto tx_error;
		}
	}
	tdev = rt->u.dst.dev;

	max_headroom = LL_RESERVED_SPACE(tdev) + sizeof(*iph)+sizeof(*hdr)+2;

	if (!skb){
		skb=dev_alloc_skb(max_headroom);
		skb_reserve(skb,max_headroom-skb_headroom(skb));
	}
	else if (skb_headroom(skb) < max_headroom || skb_cloned(skb) || skb_shared(skb)) {
		struct sk_buff *new_skb = skb_realloc_headroom(skb, max_headroom);
		if (!new_skb) {
			ip_rt_put(rt);
			goto tx_error;
		}
		if (skb->sk)
			skb_set_owner_w(new_skb, skb->sk);
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	if (skb->len){
		int islcp;
		unsigned char *data=skb->data;
		islcp=((data[0] << 8) + data[1])== PPP_LCP && 1 <= data[2] && data[2] <= 7;
		if ((ch->flags & SC_COMP_AC) == 0 || islcp) {
			data=skb_push(skb,2);
			data[0]=0xff;
			data[1]=0x03;
		}else if (*data==0 && (ch->flags & SC_COMP_PROT)){
			//data++,len--,off=1;
			skb_pull(skb,1);
		}
		//printk("%02x %02x %02x %02x %02x\n",skb->data[0],skb->data[1],skb->data[2],skb->data[3],skb->data[4]);
	}
	len=skb->len;

	if (len==0) header_len-=sizeof(hdr->seq);
	if (ch->ack_sent == ch->seq_recv) header_len-=sizeof(hdr->ack);

	skb->nh.raw = skb_push(skb, sizeof(*iph)+header_len);
	//memset(skb->nh.raw,0,(sizeof(struct iphdr) >> 2));
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
	IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED |
			      IPSKB_REROUTED);
	#endif
	dst_release(skb->dst);
	skb->dst = &rt->u.dst;

	/*
	 *	Push down and install the IP header.
	 */
	//printk("s1=%i s2=%i s3=%i s4=%i\n",sizeof(*iph),(sizeof(struct iphdr) >> 2),

	iph 			=	skb->nh.iph;
	iph->version		=	4;
	iph->ihl		=	sizeof(struct iphdr) >> 2;
	iph->frag_off		=	0;//df;
	iph->protocol		=	IPPROTO_GRE;
	iph->tos		=	0;
	iph->daddr		=	rt->rt_dst;
	iph->saddr		=	rt->rt_src;
	iph->ttl = dst_metric(&rt->u.dst, RTAX_HOPLIMIT);

	hdr=(struct pptp_gre_header *)(iph+1);
	skb->h.raw = (char*)hdr;

	hdr->flags       = hton8 (PPTP_GRE_FLAG_K);
	hdr->ver         = hton8 (PPTP_GRE_VER);
	hdr->protocol    = hton16(PPTP_GRE_PROTO);
	hdr->call_id     = hton16(ch->peer_call_id);

	if (!len){
		hdr->payload_len = 0;
		hdr->ver |= hton8(PPTP_GRE_FLAG_A);
		/* ack is in odd place because S == 0 */
		hdr->seq = hton32(ch->seq_recv);
		ch->ack_sent = ch->seq_recv;
		//printk("send_ack %i %i\n",ch->seq_recv,skb->len);
	}else {
		if (!ch->seq_sent){
			char unit[10];
			sprintf(unit,"ppp%i",ppp_unit_number(&ch->ppp_chan));
			create_proc_read_entry(unit,0,proc_dir,read_proc,ch);
		}

		hdr->flags |= hton8(PPTP_GRE_FLAG_S);
		hdr->seq    = hton32(ch->seq_sent++);
		if (log_level>=2)
			printk("PPTP: send packet: seq=%i",ch->seq_sent);
		if (ch->ack_sent != ch->seq_recv)	{
		/* send ack with this message */
				hdr->ver |= hton8(PPTP_GRE_FLAG_A);
				hdr->ack  = hton32(ch->seq_recv);
				ch->ack_sent = ch->seq_recv;
				if (log_level>=2)
					printk(" ack=%i",ch->seq_recv);
		}
		hdr->payload_len = hton16(len);
		if (log_level>=2)
			printk("\n");
	}

	nf_reset(skb);

	skb->ip_summed = CHECKSUM_NONE;
	iph->tot_len = htons(skb->len);
	ip_select_ident(iph, &rt->u.dst, NULL);
	ip_send_check(iph);

	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev, dst_output);
	if (err == NET_XMIT_SUCCESS || err == NET_XMIT_CN) {
		ch->stats.tx_sent++;
		ch->stats.pt.seq  = ch->seq_sent;
		ch->stats.pt.time = get_jiffies_64();
	} else {
		ch->stats.tx_failed++;
	}

	return 1;

tx_error:
	ch->stats.tx_failed++;
	if (!len) dev_kfree_skb(skb);
	return 0;
}




static void check_ack_timer(unsigned long data)
{
	struct pptp_chan_t *ch=(struct pptp_chan_t *)data;
	if (ch->ack_sent != ch->seq_recv){
		process_outgoing_skb(&ch->ppp_chan,0);
	}
}
static int get_seq(struct sk_buff *skb)
{
	struct iphdr *iph;
	u8 *payload;
  struct pptp_gre_header *header;

	iph = (struct iphdr*)skb->data;
	payload = skb->data + (iph->ihl << 2);

	header = (struct pptp_gre_header *)(payload);

	return ntoh32(header->seq);
}
static void check_buf_timer(unsigned long data)
{
	struct timeval tv;
	struct sk_buff *skb;
	struct pptp_chan_t *ch=(struct pptp_chan_t *)data;
	unsigned int t;

	//printk("PPTP: check_buf_timer ch=%p call_id=%i\n",ch,ch->call_id);
	write_lock(&ch->skb_buf_lock);
	while((skb=skb_dequeue(&ch->skb_buf))){
		if (!process_incoming_skb(ch,skb,0)){
			do_gettimeofday(&tv);
			t=(tv.tv_sec-skb->tstamp.off_sec)*HZ+(tv.tv_usec-skb->tstamp.off_usec)*HZ/1000000;
			//printk("t=%i rtt=%i\n",t,ch->stats.rtt);
			if (t<ch->stats.rtt){
				skb_queue_head(&ch->skb_buf,skb);
				mod_timer(&ch->buf_timer,jiffies+ch->stats.rtt-t);
				goto exit;
			}
			t=get_seq(skb)-1;
			ch->stats.rx_lost+=t-ch->seq_recv;
			ch->seq_recv=t;
			process_incoming_skb(ch,skb,0);
		}
	}
	if (timer_pending(&ch->buf_timer))
		del_timer(&ch->buf_timer);
exit:
	write_unlock(&ch->skb_buf_lock);
}


#define MISSING_WINDOW 20
#define WRAPPED( curseq, lastseq) \
    ((((curseq) & 0xffffff00) == 0) && \
     (((lastseq) & 0xffffff00 ) == 0xffffff00))
static int process_incoming_skb(struct pptp_chan_t *ch,struct sk_buff *skb,int new)
{
	int headersize,payload_len,seq;
	u8 *payload;
  struct pptp_gre_header *header;

	header = (struct pptp_gre_header *)(skb->data);

	if (new){
		/* test if acknowledgement present */
		if (PPTP_GRE_IS_A(ntoh8(header->ver))){
				u_int32_t ack = (PPTP_GRE_IS_S(ntoh8(header->flags)))?
						header->ack:header->seq; /* ack in different place if S = 0 */
				ack = ntoh32( ack);
				if (ack > ch->ack_recv) ch->ack_recv = ack;
				/* also handle sequence number wrap-around  */
				if (WRAPPED(ack,ch->ack_recv)) ch->ack_recv = ack;
				//printk("PPTP: ack_recv=%i seq=%i\n",ch->ack_recv ,ch->stats.pt.seq);
				if (ch->ack_recv+1 == ch->stats.pt.seq){
						int rtt = get_jiffies_64() - ch->stats.pt.time;
						ch->stats.rtt = (ch->stats.rtt + rtt) / 2;
						if (ch->stats.rtt>ch->timeout) ch->stats.rtt=ch->timeout;
				}
				if (ch->pause){
					ch->pause=0;
					ppp_output_wakeup(&ch->ppp_chan);
				}
		}

		/* test if payload present */
		if (!PPTP_GRE_IS_S(ntoh8(header->flags)))
				goto drop;
	}

	headersize  = sizeof(*header);
	payload_len = ntoh16(header->payload_len);
	seq         = ntoh32(header->seq);

	/* no ack present? */
	if (!PPTP_GRE_IS_A(ntoh8(header->ver))) headersize -= sizeof(header->ack);
	/* check for incomplete packet (length smaller than expected) */
	if (skb->len- headersize < payload_len){
			if (log_level>=1)
				printk("PPTP: discarding truncated packet (expected %d, got %d bytes)\n",
							payload_len, skb->len- headersize);
			ch->stats.rx_truncated++;
			goto drop;
	}

	payload=skb->data+headersize;
	/* check for expected sequence number */
	if ((seq == ch->seq_recv + 1) || (!ch->timeout && (seq > ch->seq_recv + 1 || WRAPPED(seq, ch->seq_recv)))){ /* wrap-around safe */
		if ( log_level >= 2 )
			printk("PPTP: accepting packet %d size=%i (%02x %02x %02x %02x %02x %02x\n", seq,payload_len,
				*(payload +0),
				*(payload +1),
				*(payload +2),
				*(payload +3),
				*(payload +4),
				*(payload +5));
		ch->stats.rx_accepted++;
		ch->stats.rx_lost+=seq-(ch->seq_recv + 1);
		//first = 0;
		ch->seq_recv = seq;
		if (ch->seq_recv!=ch->ack_sent)
			mod_timer(&ch->ack_timer,jiffies+(ch->ack_sent+1==ch->seq_recv?HZ/20:0));

		skb_pull(skb,headersize);

		if (payload[0] == PPP_ALLSTATIONS && payload[1] == PPP_UI){
			/* chop off address/control */
			if (skb->len < 3)
				return 1;
			skb_pull(skb,2);
		}

		if ((*skb->data) & 1){
			/* protocol is compressed */
			skb_push(skb, 1)[0] = 0;
		}

		ppp_input(&ch->ppp_chan,skb);

		return 1;
	/* out of order, check if the number is too low and discard the packet.
	* (handle sequence number wrap-around, and try to do it right) */
	}else if ( seq < ch->seq_recv + 1 || WRAPPED(ch->seq_recv, seq) ){
		if ( log_level >= 1)
			printk("PPTP: discarding duplicate or old packet %d (expecting %d)\n",
							seq, ch->seq_recv + 1);
		ch->stats.rx_underwin++;
	/* sequence number too high, is it reasonably close? */
	}else if ( seq < ch->seq_recv + MISSING_WINDOW ||	WRAPPED(seq, ch->seq_recv + MISSING_WINDOW) ){
		ch->stats.rx_buffered++;
		if ( log_level >= 1 && new )
				printk("PPTP: %s packet %d (expecting %d, lost or reordered)\n",
							"buffering",
						seq, ch->seq_recv+1);
		return 0;
	/* no, packet must be discarded */
	}else{
		if ( log_level >= 1 )
			printk("PPTP: discarding bogus packet %d (expecting %d)\n",
							seq, ch->seq_recv + 1);
			ch->stats.rx_overwin++;
	}
drop:
	return -1;
}


static int pptp_rcv(struct sk_buff *skb)
{
  struct pptp_gre_header *header;
  struct pptp_chan_t *ch;

	if (!pskb_may_pull(skb, 12))
		goto drop_nolock;

	header = (struct pptp_gre_header *)skb->data;

	if (    /* version should be 1 */
					((ntoh8(header->ver) & 0x7F) != PPTP_GRE_VER) ||
					/* PPTP-GRE protocol for PPTP */
					(ntoh16(header->protocol) != PPTP_GRE_PROTO)||
					/* flag C should be clear   */
					PPTP_GRE_IS_C(ntoh8(header->flags)) ||
					/* flag R should be clear   */
					PPTP_GRE_IS_R(ntoh8(header->flags)) ||
					/* flag K should be set     */
					(!PPTP_GRE_IS_K(ntoh8(header->flags))) ||
					/* routing and recursion ctrl = 0  */
					((ntoh8(header->flags)&0xF) != 0))
	{
			/* if invalid, discard this packet */
			if (log_level>=1)
			printk("PPTP: Discarding GRE: %X %X %X %X %X %X\n",
							ntoh8(header->ver)&0x7F, ntoh16(header->protocol),
							PPTP_GRE_IS_C(ntoh8(header->flags)),
							PPTP_GRE_IS_R(ntoh8(header->flags)),
							PPTP_GRE_IS_K(ntoh8(header->flags)),
							ntoh8(header->flags) & 0xF);
			goto drop_nolock;
	}

	read_lock(&chan_lock);

	dst_release(skb->dst);
	skb->dst = NULL;
	nf_reset(skb);

	if ((ch=lookup_chan(hton16(header->call_id))))
	{
		if (process_incoming_skb(ch,skb,1)){
			check_buf_timer((unsigned long)ch);
		}else{
			write_lock(&ch->skb_buf_lock);
			skb_queue_tail(&ch->skb_buf, skb);
			write_unlock(&ch->skb_buf_lock);
			if (!timer_pending(&ch->buf_timer))
				mod_timer(&ch->buf_timer,jiffies+ch->stats.rtt?ch->stats.rtt:1);
		}
		read_unlock(&chan_lock);
		return 0;
	}else icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PROT_UNREACH, 0);

	read_unlock(&chan_lock);
drop_nolock:
	kfree_skb(skb);
	return(0);
}



/*
 * The following routines provide the PPP channel interface.
 */
static int ppp_ioctl(struct ppp_channel *chan, unsigned int cmd, unsigned long arg)
{
	struct pptp_chan_t *ap = chan->private;
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int err, val;

	err = -EFAULT;
	switch (cmd) {
	case PPPIOCGFLAGS:
		val = ap->flags;
		if (put_user(val, p))
			break;
		err = 0;
		break;
	case PPPIOCSFLAGS:
		if (get_user(val, p))
			break;
		printk("PPTP: PPPIOCSFLAGS: %X\n",val);
		ap->flags = val;
		err = 0;
		break;

	default:
		err = -ENOTTY;
	}

	return err;
}



static int proc_output (struct pptp_chan_t *ch,char *buf)
{
	char *p=buf;
	p+=sprintf(p,"rx accepted  = %d\n",ch->stats.rx_accepted);
	p+=sprintf(p,"rx lost      = %d\n",ch->stats.rx_lost);
	p+=sprintf(p,"rx under win = %d\n",ch->stats.rx_underwin);
	p+=sprintf(p,"rx over win  = %d\n",ch->stats.rx_overwin);
	p+=sprintf(p,"rx buffered  = %d\n",ch->stats.rx_buffered);
	p+=sprintf(p,"rx invalid   = %d\n",ch->stats.rx_invalid);
	p+=sprintf(p,"rx acks      = %d\n",ch->stats.rx_acks);
	p+=sprintf(p,"tx sent      = %d\n",ch->stats.tx_sent);
	p+=sprintf(p,"tx failed    = %d\n",ch->stats.tx_failed);
	p+=sprintf(p,"tx acks      = %d\n",ch->stats.tx_acks);

	return p-buf;
}
static int read_proc(char *page, char **start, off_t off,int count, int *eof, void *data)
{
	struct pptp_chan_t *ch = data;
	int len = proc_output (ch,page);
	if (len <= off+count) *eof = 1;
	*start = page + off;
	len -= off;
	if (len>count) len = count;
	if (len<0) len = 0;
	return len;
}



static int pptp_connect(struct file *file,struct pptp_conn_t *conn)
{
	int err=0;
	struct pptp_chan_t *ch;

	if (log_level>=1)
		printk("PPTP: connect: call_id=%i peer_call_id=%i s_addr=%X d_addr=%X window=%i\n",conn->call_id,conn->peer_call_id,conn->loc_addr.s_addr,conn->sin_addr.s_addr,conn->window);

	ch=kmalloc(sizeof(*ch),GFP_KERNEL);
	memset(ch,0,sizeof(*ch));

	ch->timeout=conn->timeout?(conn->timeout/1000*HZ?conn->timeout/1000*HZ:1):0;
	ch->stats.rtt=ch->timeout;
	ch->seq_recv=-1;
	ch->ack_sent=-1;
	ch->window=conn->window;
	if (ch->window>max_window) ch->window=max_window;
	if (ch->window<min_window) ch->window=min_window;

	ch->call_id=conn->call_id;
	ch->peer_call_id=conn->peer_call_id;
	ch->dst_addr=conn->sin_addr;
	ch->src_addr=conn->loc_addr;
	ch->mru=PPP_MRU;
	ch->ppp_chan.private=ch;
	ch->ppp_chan.ops=&pptp_chan_ops;
	ch->ppp_chan.mtu=PPP_MTU;
	ch->ppp_chan.hdrlen=2+sizeof(struct pptp_gre_header);
	err = ppp_register_channel(&ch->ppp_chan);
	if (err){
		printk(KERN_ERR "PPTP: failed to register PPP channel (%d)\n",err);
		kfree(ch);
		return err;
	}

	skb_queue_head_init(&ch->skb_buf);
	ch->skb_buf_lock=RW_LOCK_UNLOCKED;
	init_timer(&ch->ack_timer);
	init_timer(&ch->buf_timer);
	ch->ack_timer.function=check_ack_timer;
	ch->ack_timer.data=(unsigned long)ch;
	ch->buf_timer.function=check_buf_timer;
	ch->buf_timer.data=(unsigned long)ch;

	write_lock(&chan_lock);
	list_add_tail(&ch->entry,chans+HASH(ch->call_id));
	file->private_data=ch;
	write_unlock(&chan_lock);

	//printk("PPTP: successfuly opened channel\n");
	return 0;
}

static int pptp_open(struct inode *inode, struct file *file)
{
	/*
	 * This could (should?) be enforced by the permissions on /dev/pptp.
	 */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	return 0;
}

static int pptp_release(struct inode *inode, struct file *file)
{
	struct pptp_chan_t *ch=(struct pptp_chan_t*)file->private_data;
	if (ch){
		if (ch->seq_sent){
			char unit[10];
			sprintf(unit,"ppp%i",ppp_unit_number(&ch->ppp_chan));
			remove_proc_entry(unit,proc_dir);
		}

		write_lock_bh(&chan_lock);
		ppp_unregister_channel(&ch->ppp_chan);
		list_del(&ch->entry);
		del_timer(&ch->ack_timer);
		del_timer(&ch->buf_timer);
		write_unlock_bh(&chan_lock);

		skb_queue_purge(&ch->skb_buf);

		kfree(ch);
		file->private_data=NULL;
	}
	return 0;
}

static int pptp_ioctl(struct inode *inode, struct file *file,
		     unsigned int cmd, unsigned long arg)
{
	struct pptp_chan_t *ch=(struct pptp_chan_t*)file->private_data;

	switch (cmd)
	{
		case PPPIOCGCHAN:
		{
			int index;
			if (!ch) return -ENOTCONN;
			index = ppp_channel_index(&ch->ppp_chan);
			if (put_user(index , (int __user *) arg))
				return -EFAULT;

			return 0;
		}
		case PPPIOCCONNECT:
		{
			struct pptp_conn_t conn;
			if (ch && ch->call_id) return -EBUSY;
			if (copy_from_user(&conn,(void __user*)arg,sizeof(conn)))
				return -EFAULT;
			return pptp_connect(file,&conn);
		}
	};
	return -EINVAL;
}

static struct file_operations pptp_device_fops = {
	.owner		= THIS_MODULE,
	.ioctl		= pptp_ioctl,
	.open		= pptp_open,
	.release	= pptp_release,
};


static struct net_protocol pptp_protocol = {
	.handler	= pptp_rcv,
	//.err_handler	=	ipgre_err,
};


static int pptp_init_module(void)
{
	int i,err;
	printk(KERN_INFO "PPTP driver version " PPTP_DRIVER_VERSION "\n");

	if (inet_add_protocol(&pptp_protocol, IPPROTO_GRE) < 0) {
		printk(KERN_INFO "PPTP: can't add protocol\n");
		return -EAGAIN;
	}

	err = register_chrdev(PPTP_MAJOR, "pptp", &pptp_device_fops);
	if (err){
		printk(KERN_ERR "PPTP: failed to register PPTP device (%d)\n", err);
		inet_del_protocol(&pptp_protocol, IPPROTO_GRE);
		return err;
	}

	proc_dir=proc_mkdir("pptp",NULL);
	if (!proc_dir){
		printk(KERN_ERR "PPTP: failed to create proc dir\n");
	}
	//console_verbose();
	for(i=0; i<HASH_SIZE; i++)
		INIT_LIST_HEAD(chans+i);

	return 0;
}

static void pptp_exit_module(void)
{
	inet_del_protocol(&pptp_protocol, IPPROTO_GRE);
	if (unregister_chrdev(PPTP_MAJOR, "pptp") != 0)
		printk(KERN_ERR "PPTP: failed to unregister PPTP device\n");
	if (proc_dir){
		remove_proc_entry("pptp",NULL);
	}
}


module_init(pptp_init_module);
module_exit(pptp_exit_module);
