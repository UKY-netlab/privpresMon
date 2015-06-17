/*
 * nfl.c
 * By Xuzi Zhou
 *
 * # Define a flow #
 * In our module, we define a network flow as:
 *  - Use the combination of src/dst IP addresses and src/dst port numbers 
 *    as the key of a flow
 *  - A flow is unidirectional (The packets from counter direction belong to
 *    another flow)
 *  - If a new packet comes with TCP FIN flag on and the packet doesn't belong
 *    to any existing flow, we just ignore the packet.
 *  - A flow expires. 
 *    - Expire by timeout. We set the default expiration time as five minutes 
 *      for an active flow. That means if we don't see any new packets of an 
 *      existing flow for five minutes, we will expire the flow.
 *    - Expire by speical packet. If we see a packet with FIN flag on for a 
 *      TCP flow, we expire the flow thereafter.
 *
 *
 * # Collect flow data #
 * The kernel module, nfl_mod, is implemented to collected flow data from
 * all IP packets going through the NetFilter system. The nfl_mod is designed
 * to work on the gateway router of a home network, which can observe almost
 * all IP-level packets transmitted in its local home network.
 *
 * Pool of NetFilter hooks:
 *  NF_IP_PRE_ROUTING (default)
 *  NF_IP_LOCAL_OUT (default)
 *  NF_BR_FORWARD
 *
 * # NFL statistics #
 * We maintain a data structure in the NFL kernel module to keep track of 
 * statistics of all flows passing through. 
 *
 * The statistics collected:
 * 
 *
 * # Maintain active flows #
 * We first store the data information of a captured flow in a hash table,
 * using modified UTHash(http://troydhanson.github.io/uthash/). As long as a
 * flow is still active, we keep the flow entry in the hash table and update
 * its statistics on receiving any new packets of the flow. We consider a flow
 * to be inactive if we haven't seen any packets of a flow for five minutes. 
 *
 * UTHash is modified by:
 * - Add CRC32 as the default hash function
 * - Add Linux spin lock support to hash table buckets
 * - Increase the default initial number of buckets from 256 to 512
 *
 *
 * # Flow information #
 * We keep the following information for a flow:
 * - Flow Key:
 *   - Transport layer protocol number
 *   - Source IP address
 *   - Destination IP address
 *   - Source port number
 *   - Destination port number
 * - Time stamps:
 *   - Flow start time
 *   - Start time of the current capturing interval
 *   - Flow end time (expiration time)
 * - Statistics:
 *   - Number of packets
 *   - Number of bytes
 * 
 *
 * # Store expired flows #
 * We expire an inactive flow and temporarily store the expired flow in a
 * linked list. We maintain the linked list (expire_list) for expired flows 
 * until the export operation.
 * 
 * # Export flows #
 * We export flows by writing flow data to the Linux proc filesystem. Due to
 * the large size of flow data (probably larger than a page), we utilize the
 * seq_file to manage the output to procfs (/proc/nfl_mod). We export the 
 * flows in expire_list along with all active flows in the hash table. A user
 * space helper process, nfl_c, decides when to triger the exporting operation,
 * collects exported flows, and mainnew_dns_masktains a database for all the flows.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ip.h>
#include <linux/timer.h>
#include <linux/time.h>
#include "uthash.h"
#include "nfl.h"
#include "nfl_functions.h"


int log_host_stat = 0;
#ifndef NO_PRE_ROUTING
struct nf_hook_ops nfho_ip_pre;
#endif
#ifndef NO_LOCAL_OUT
struct nf_hook_ops nfho_ip_out;
#endif
#ifdef BR_FORWARD
struct nf_hook_ops nfho_br_fwd;
#endif
struct ipflowstat ipflow_stat;
struct ipflow *ipflow_hhead = NULL;
struct ipflow_exp_stat *expire_lhead, *export_lhead;
static struct kmem_cache *ipflow_cache;
static struct kmem_cache *ipflow_exp_cache;
static struct proc_dir_entry *proc_nfl;
static struct proc_dir_entry *proc_nfl_stat;
int seq_track = 0;
int dns_mask = DNS_MASK_PORT_START;
spinlock_t ht_lock;		/* Hash table spinlock */
spinlock_t expire_lock;	/* Expire list spinlock */
spinlock_t export_lock; /* Export list spinlock */
spinlock_t dns_mask_lock; /* DNS mask port number spinlock */


void flow_expire(unsigned long data)
{
	struct ipflow_exp *aflow_exp;
	struct ipflow *aflow = (struct ipflow *)data;
	struct ipflow_exp *del_flow_exp, *tmp_flow_exp;
	int del_count = 0;

	/* Remove flow from hash table */
	BKT_LOCK(aflow);
	HASH_DEL(ipflow_hhead, aflow);
	BKT_UNLOCK(aflow);

	/* Copy flow info to ipflow_exp list */
	spin_lock(&expire_lock);

	/* Remove X oldest expired flows if limit reached*/
	if(expire_lhead->expired_count >= MAX_EXPIRE_LIST_SIZE){
		list_for_each_entry_safe(del_flow_exp, tmp_flow_exp, 
				&(export_lhead->exp_list), exp_list){
			list_del(&del_flow_exp->exp_list);
			kmem_cache_free(ipflow_exp_cache, del_flow_exp);
			del_count += 1;
			if(del_count == EXPIRE_LIST_THR){
				break;
			}
		}
		expire_lhead->expired_count -= del_count;
	}
	
	UPDATE_EXPIRE_LIST(aflow, aflow_exp, expire_lhead);
	spin_unlock(&expire_lock);

	del_timer(&aflow->flow_timer);				
	kmem_cache_free(ipflow_cache, aflow);

	spin_lock(&ipflow_stat.flowstat_lock);
	ipflow_stat.expired_flows = expire_lhead->expired_count;
	ipflow_stat.active_flows -= 1;
	spin_unlock(&ipflow_stat.flowstat_lock);
}

/*
 * capture_ipflow(): NetFilter hook function to caputure IP flows
 */
unsigned int capture_ipflow(unsigned int hooknum,struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct ipflow *tmp_ipflow;
	struct ipflowkey tmp_flowkey;
	struct sk_buff *sock_buff;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmphdr *icmp_header;
	struct timeval tv;

	do_gettimeofday(&tv);	
	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	if(!sock_buff)
		return NF_ACCEPT;
	/* Update flow hash table */
	switch(ip_header->protocol){
	case IPPROTO_TCP:
		tcp_header = (struct tcphdr *)
				(skb_network_header(sock_buff)
				+ ip_hdrlen(sock_buff));
		if(tcp_header) {
			/* Assign flow key*/
			ASSIGN_FLOWKEY_TCP_UDP(tmp_flowkey,
					ip_header, tcp_header);
		}
		break;	/* End of case IPPROTO_TCP */
	case IPPROTO_UDP:
		udp_header = (struct udphdr *)
				(skb_network_header(sock_buff) 
				+ ip_hdrlen(sock_buff));
		if(udp_header) {
			/* Assign flow key*/
			ASSIGN_FLOWKEY_TCP_UDP(tmp_flowkey,
					ip_header, udp_header);
			/* Mask port in DNS flow */
			spin_lock(&dns_mask_lock);
			MASK_DNS(tmp_flowkey);
			spin_unlock(&dns_mask_lock);
		}
		break;	/* End of case IPPROTO_UDP */
	case IPPROTO_ICMP:
		icmp_header = (struct icmphdr *)
				(skb_network_header(sock_buff)
				+ ip_hdrlen(sock_buff));
		if(icmp_header){
			/* Assign flow key*/
			ASSIGN_FLOWKEY_ICMP(tmp_flowkey,
					ip_header, icmp_header);
		}
		break;	/* End of case IPPROTO_ICMP */
	default:
		ASSIGN_FLOWKEY_OTHER(tmp_flowkey, ip_header);
	}	/* End of switch(ip_header->protocol) */
	/* Find flow in hash table */
	HASH_FIND(hh, ipflow_hhead, &tmp_flowkey,
			sizeof(struct ipflowkey), tmp_ipflow);
	/* Create new flow if no matching flow is found */
	if(tmp_ipflow == NULL){
		if(HASH_COUNT(ipflow_hhead)<MAX_FLOW_TABLE_SIZE){
			tmp_ipflow = kmem_cache_alloc(ipflow_cache, GFP_KERNEL);
			INIT_IPFLOW(tmp_ipflow, tmp_flowkey, ipflow_stat, 
						tv, ip_header);
			ADD_NEW_IPFLOW(tmp_ipflow, ipflow_hhead, ipflow_stat);
			UPDATE_FLOWSTAT_PKT(ip_header, ipflow_stat);
		}
	} else  {
		UPDATE_IPFLOW(tmp_ipflow);
		UPDATE_FLOWSTAT_PKT(ip_header, ipflow_stat);
		if(get_time_offset(tmp_ipflow->start,tv)/NSEC_IN_A_MSEC
				>= FORCE_TIMEOUT){
			flow_expire((unsigned long)tmp_ipflow);
		}
	}
	return NF_ACCEPT;
}

/* Prepare export data*/
static void prep_exp(void)
{
	struct ipflow *aflow, *tmp_flow;
	struct ipflow_exp *aflow_exp;
	struct timeval tv;

	spin_lock(&dns_mask_lock);
	dns_mask = new_dns_mask(dns_mask);
	spin_unlock(&dns_mask_lock);

	do_gettimeofday(&tv);

	spin_lock(&export_lock);
	spin_lock(&expire_lock);
	ptr_swap(&expire_lhead, &export_lhead);
	spin_unlock(&expire_lock);
	HASH_ITER(hh, ipflow_hhead, aflow, tmp_flow){
		BKT_LOCK(aflow);
		UPDATE_EXPORT_LIST(aflow, aflow_exp, export_lhead, tv);
		BKT_UNLOCK(aflow);
	}
	spin_unlock(&export_lock);
#ifdef NFL_DEBUG
	printk(KERN_INFO "%s\n", __func__);
#endif
}

static void init_exp(void)
{
	struct ipflow_exp *aflow_exp, *tmp_flow_exp;
	spin_lock(&export_lock);
	list_for_each_entry_safe(aflow_exp, tmp_flow_exp, 
				&(export_lhead->exp_list), exp_list) {
		list_del(&aflow_exp->exp_list);
		kmem_cache_free(ipflow_exp_cache, aflow_exp);
	}
	INIT_EXP_LHEAD(export_lhead);
	spin_unlock(&export_lock);
}

/* seq_file functions 
 * 1. proc_seq_start()
 * 2. proc_seq_next()
 * 3. proc_seq_stop()
 * 4. proc_seq_show()
 *
 * Ring of function calls:
 * proc_seq_start() -> proc_seq_show() -> proc_seq_stop()
 *     ^   ^                                    | |
 *     |   |____________________________________v |
 *     |                                          V
 *     |_________________________________proc_seq_next()
 */
static void *proc_seq_start(struct seq_file *s, loff_t * pos)
{
#ifdef NFL_DEBUG
	printk(KERN_INFO "%s()  pos = %lld\n", __func__, *pos);
#endif
	if (*pos == 0){
#ifdef NFL_DEBUG
		printk(KERN_INFO "seq_track = %d", seq_track);
#endif
		if (seq_track == 0) {
			prep_exp();
			seq_track += 1;
		}
		return export_lhead;
	}
	else{
		seq_track = 0;
		init_exp();
		return NULL;
	}
}

static void *proc_seq_next(struct seq_file *s, void *v, loff_t * pos)
{
#ifdef NFL_DEBUG
	printk(KERN_INFO "%s()\n", __func__);
#endif
	(*pos)++;
	return NULL;
}

static void proc_seq_stop(struct seq_file *s, void *v)
{
#ifdef NFL_DEBUG
	printk(KERN_INFO "%s()\n", __func__);
#endif
}

static int proc_seq_show(struct seq_file *s, void *v)
{
	//struct ipflow_exp_stat *exp_lhead = (struct ipflow_exp_stat *)v;
	struct ipflow_exp *aflow_exp, *tmp_flow_exp;
	spin_lock(&export_lock);
#ifdef NFL_DEBUG
	printk(KERN_INFO "%s()\n", __func__);
	printk(KERN_INFO "Expire List: #E %llu #A %llu\n", 
			expire_lhead->expired_count,
			expire_lhead->active_count);
	printk(KERN_INFO "Export List: #E %llu #A %llu\n", 
			export_lhead->expired_count,
			export_lhead->active_count);
#endif
	seq_write(s, export_lhead, sizeof(struct ipflow_exp_stat));
	list_for_each_entry_safe(aflow_exp, tmp_flow_exp, 
				&(export_lhead->exp_list), exp_list) {
		seq_write(s, aflow_exp, sizeof(struct ipflow_exp));
	}
	spin_unlock(&export_lock);
	return 0;
}

static struct seq_operations proc_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = proc_seq_show,
};

static int proc_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &proc_seq_ops);
}

static struct file_operations proc_ops = {
	.owner = THIS_MODULE,
	.open = proc_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

int nfl_stat_read( char *page, char **start, off_t off,
					int count, int *eof, void *data )
{
	int len;
	if (off > 0) {
		*eof = 1;
		return 0;
	}
	len = sprintf(page, "NFL current statistics:\n"
						"  # Hash table entries: %d\n"
						"  # Active Flows: %llu\n"
						"  # Expired Flows: %llu\n"
						"NFL lifetime statistics:\n"
						"  # Flows: %llu\n"
						"  # Packets: %llu\n"
						"  # Bytes: %llu\n",
						HASH_COUNT(ipflow_hhead),
						ipflow_stat.active_flows,
						ipflow_stat.expired_flows,
						ipflow_stat.total_flows,
						ipflow_stat.total_pkts,
						ipflow_stat.total_bytes);
	return len;
}


int init_module()
{
	ipflow_cache = KMEM_CACHE(ipflow, SLAB_HWCACHE_ALIGN);
	ipflow_exp_cache = KMEM_CACHE(ipflow_exp, SLAB_HWCACHE_ALIGN);
	expire_lhead = kmalloc(sizeof(struct ipflow_exp_stat), GFP_KERNEL);
	export_lhead = kmalloc(sizeof(struct ipflow_exp_stat), GFP_KERNEL);
	if(!expire_lhead || !export_lhead){
		printk(KERN_INFO "Cannot allocate memory.\n");
		return -ENOMEM;
	}
	/* Initialize locks */
	ht_lock = __SPIN_LOCK_UNLOCKED(ht_lock);
	expire_lock = __SPIN_LOCK_UNLOCKED(expire_lock);
	export_lock = __SPIN_LOCK_UNLOCKED(export_lock);
	dns_mask_lock = __SPIN_LOCK_UNLOCKED(dns_mask_lock);

	printk(KERN_INFO "Registering IP Packet Logging Module...\n");

	INIT_IPFLOW_STAT(ipflow_stat);
	INIT_EXP_LHEAD(expire_lhead);
	INIT_EXP_LHEAD(export_lhead);
	/* Netfilter hook config for NFPROTO_IPV4 */
	/*   NF_IP_PRE_ROUTING */
#ifndef NO_PRE_ROUTING 
	INIT_NFHO(nfho_ip_pre,capture_ipflow,
			NF_IP_PRE_ROUTING,NFPROTO_IPV4,NF_IP_PRI_LAST);
#endif
	/*   NF_IP_LOCAL_OUT */
#ifndef NO_LOCAL_OUT
	INIT_NFHO(nfho_ip_out,capture_ipflow,
			NF_IP_LOCAL_OUT,NFPROTO_IPV4,NF_IP_PRI_LAST);
#endif
	/* Netfilter hook config for NFPROTO_BRIDGE */
	/*   NF_BR_FORWARD */
#ifdef BR_FORWARD
	INIT_NFHO(nfho_br_fwd,capture_ipflow,
			NF_BR_FORWARD,NFPROTO_BRIDGE,NF_BR_PRI_LAST);
#endif
	/* procfs */
	proc_nfl = create_proc_entry("nfl_mod", 0644, NULL);
	if (proc_nfl == NULL) {
		printk(KERN_INFO "Cannot create proc entry for nfl_mod.\n");
		return -ENOMEM;
	} else {
		proc_nfl->proc_fops = &proc_ops;
	}
	proc_nfl_stat = create_proc_entry("nfl_mod_stat", 0644, NULL);
	if (proc_nfl_stat == NULL) {
		printk(KERN_INFO "Cannot create proc entry for nfl_mod_stat.\n");
		return -ENOMEM;
	} else {
		proc_nfl_stat->read_proc = nfl_stat_read;
	}
#ifdef NFL_DEBUG
	printk(KERN_INFO "IP Packet Logging Module Registered.\n");
	printk(KERN_INFO "Size of ipflow_exp: %d\n", sizeof(struct ipflow_exp));
	printk(KERN_INFO "Size of timeval: %d\n", sizeof(struct timeval));
	printk(KERN_INFO "Size of list_head: %d\n", sizeof(struct list_head));
#endif
	return 0;
}

void cleanup_module()
{
	struct ipflow *aflow, *tmp_flow;
	struct ipflow_exp *aflow_exp, *tmp_flow_exp;
#ifdef NFL_DEBUG
	uint32_t bkt;
	int i=1;
	struct tm broken_s, broken_e;
#endif

#ifndef NO_PRE_ROUTING
	nf_unregister_hook(&nfho_ip_pre);
#endif
#ifndef NO_LOCAL_OUT
	nf_unregister_hook(&nfho_ip_out);
#endif
#ifdef BR_FORWARD
	nf_unregister_hook(&nfho_br_fwd);
#endif
	/* Output all flow info and clear flows in memory */
	/* Free the memory occupied by flows */
	HASH_ITER(hh, ipflow_hhead, aflow, tmp_flow) {
#ifdef NFL_DEBUG
		bkt = BKT_NUM(aflow);
		time_to_tm(aflow->start.tv_sec, 0, &broken_s);
		time_to_tm(aflow->end.tv_sec, 0, &broken_e);
		printk(KERN_INFO "%d  %d/%d/%ld %d:%d:%d.%ld: Bucket #%d - %d entries.\n", 
			i,TIMESTAMP_TM(broken_s, aflow->start), bkt, 
			aflow->hh.tbl->buckets[bkt].count);
		i++;
		
		if(aflow->flow_key.protocol == IPPROTO_ICMP){
			PRINT_IPFLOW_ICMP(aflow);
		} else {
	        	PRINT_IPFLOW_TCPUDP(aflow, broken_s, broken_e);
		}
		printk(KERN_INFO "========================");
#endif
		spin_lock(&aflow->flow_lock);
		del_timer(&aflow->flow_timer);		
		HASH_DEL(ipflow_hhead, aflow);	
		spin_unlock(&aflow->flow_lock);
		kmem_cache_free(ipflow_cache, aflow);
	}
#ifdef NFL_DEBUG
	printk(KERN_INFO "========================");
	i=1;
#endif
	list_for_each_entry_safe(aflow_exp, tmp_flow_exp, 
				&(expire_lhead->exp_list), exp_list) {
#ifdef NFL_DEBUG
		printk(KERN_INFO "%u.%u.%u.%u:%d-->%u.%u.%u.%u:%d\n", 
			NIPQUAD(aflow_exp->flow_key.saddr),
			ntohs(aflow_exp->flow_key.sport),
			NIPQUAD(aflow_exp->flow_key.daddr),
			ntohs(aflow_exp->flow_key.dport));		
#endif
		list_del(&aflow_exp->exp_list);
		kmem_cache_free(ipflow_exp_cache, aflow_exp);
	}
	/* Destroy the memory cache */
	kmem_cache_destroy(ipflow_cache);
	kmem_cache_destroy(ipflow_exp_cache);
	kfree(expire_lhead);
	kfree(export_lhead);
	remove_proc_entry("nfl_mod", NULL);
	remove_proc_entry("nfl_mod_stat", NULL);
	printk(KERN_INFO "Unregistered IP Packet Logging Module\n");
}

MODULE_AUTHOR("Xuzi Zhou");
MODULE_DESCRIPTION("Kernel Network Flow Logger Module");
MODULE_LICENSE("GPL");