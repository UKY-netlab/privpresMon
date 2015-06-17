/*
 * dns_res.c
 * By Xuzi Zhou
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
#include "dnsres.h"

struct nf_hook_ops nfho_ip_in;

struct dns_record *dnstbl_hhead = NULL;
struct dns_exp_stat *export_lhead;
static struct kmem_cache *dnsrec_cache;
static struct kmem_cache *dnsrec_exp_cache;
static struct proc_dir_entry *proc_nfl_dns;
static struct proc_dir_entry *proc_nfl_dns_stat;
int seq_track = 0;
spinlock_t table_lock;
spinlock_t export_lock; /* Export list spinlock */

uint32_t rjen32_hash(__be32 *a)
{
	uint32_t b = (uint32_t)(*a);
	b = (b+0x7ed55d16) + (b<<12);
	b = (b^0xc761c23c) ^ (b>>19);
	b = (b+0x165667b1) + (b<<5);
	b = (b+0xd3a2646c) ^ (b<<9);
	b = (b+0xfd7046c5) + (b<<3);
	b = (b^0xb55a4f09) ^ (b>>16);
	return b;
}

/* Prepare export data*/
static void prep_exp(void)
{
	struct dns_record *dnsrec, *tmp_dnsrec;
	struct dns_record_exp *dnsrec_exp;

	spin_lock(&export_lock);
	HASH_ITER(hh, dnstbl_hhead, dnsrec, tmp_dnsrec){
		BKT_LOCK(dnsrec->ip);
		UPDATE_EXPORT_LIST(dnsrec, dnsrec_exp, export_lhead);
		HASH_DEL(dnstbl_hhead, dnsrec);
		BKT_UNLOCK(dnsrec->ip);		
		kmem_cache_free(dnsrec_cache, dnsrec);
	}
	spin_unlock(&export_lock);
#ifdef DNS_DEBUG
	printk(KERN_INFO "%s\n", __func__);
#endif
}

static void init_exp(void)
{
	struct dns_record_exp *dnsrec_exp, *tmp_dnsrec_exp;
	spin_lock(&export_lock);
	list_for_each_entry_safe(dnsrec_exp, tmp_dnsrec_exp, 
				&(export_lhead->exp_list), exp_list) {
		list_del(&dnsrec_exp->exp_list);
		kmem_cache_free(dnsrec_exp_cache, dnsrec_exp);
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
	if (*pos == 0){
		if (seq_track == 0) {
			prep_exp();
			seq_track += 1;
		}
		return export_lhead;
	} else{
		seq_track = 0;
		init_exp();
		return NULL;
	}
}

static void *proc_seq_next(struct seq_file *s, void *v, loff_t * pos)
{
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
	struct dns_record_exp *dnsrec_exp, *tmp_dnsrec_exp;
	spin_lock(&export_lock);
	seq_write(s, export_lhead, sizeof(struct dns_exp_stat));
	list_for_each_entry_safe(dnsrec_exp, tmp_dnsrec_exp, 
				&(export_lhead->exp_list), exp_list) {
		seq_write(s, dnsrec_exp, sizeof(struct dns_record_exp));
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

void add_dns_rec(__be32 ipkey, char qname[])
{
	struct dns_record *tmp_dnsr;
	
	HASH_FIND(hh, dnstbl_hhead, &ipkey, sizeof(__be32), tmp_dnsr);
	if(tmp_dnsr == NULL){
		tmp_dnsr = kmem_cache_alloc(dnsrec_cache, GFP_KERNEL);
		tmp_dnsr->ip = ipkey;
		strncpy(tmp_dnsr->name, qname, DNS_NAME_LEN);
		HASH_ADD(hh, dnstbl_hhead, ip, sizeof(__be32), tmp_dnsr);
	}
}

/*
 * capture_dnsrec(): NetFilter hook function to caputure DNS records
 */
unsigned int capture_dnsrec(unsigned int hooknum,struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sock_buff;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	struct dnshdr *dns_header;
	unsigned char *pkt_ptr;
	unsigned char *res_ptr;
	char ques[DNS_NAME_BUF_LEN];
	char short_name[DNS_NAME_LEN];
	int i,cptr,scptr;
	uint8_t ccnt;
	uint16_t *qtype, *qclass, *dlen;
	size_t dns_len;
	__be32 *ipaddr;
	__be32 ipkey;
	struct dns_record *tmp_dnsr;

	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	if(!sock_buff)
		return NF_ACCEPT;
	/* Update DNS record hash table */
	if(ip_header->protocol == IPPROTO_UDP){
		pkt_ptr = (unsigned char *)
				(skb_network_header(sock_buff) 
				+ ip_hdrlen(sock_buff));
		udp_header = (struct udphdr *)pkt_ptr;

		if(udp_header && udp_header->source == DNS_PORT
				&& HASH_COUNT(dnstbl_hhead)<DNS_TBL_LIMIT) {
			pkt_ptr += sizeof(struct udphdr);
			dns_len = udp_header->len - 8;
			if(12 > pkt_ptr + dns_len)
				return NF_ACCEPT;
			dns_header = (struct dnshdr *)pkt_ptr;
			if(dns_header->qr &&
					dns_header->opcode == QUERY &&
					dns_header->rcode == NOERROR &&
					dns_header->qdcount == 1 &&
					dns_header->ancount > 0){
				/* Get query name from DNS */
				res_ptr = pkt_ptr + sizeof(struct dnshdr);
				cptr = 0;
				scptr = 1 - DNS_NAME_LEN;
				while(*res_ptr != 0){
					ccnt = (uint8_t)(*res_ptr);
					res_ptr++;
					if(cptr>0){
						ques[cptr++]='.';
						scptr++;
					}
					for(i=0;i<ccnt; i++){
						ques[cptr++] = *res_ptr;
						res_ptr++;
						scptr++;
					}
				}
				if(cptr>=DNS_NAME_BUF_LEN)
					ques[DNS_NAME_BUF_LEN-1]='\0';
				else
					ques[cptr]='\0';
				/* Prepare short_name */
				if(scptr<=0){
					strncpy(short_name, ques, DNS_NAME_LEN);
				} else {
					short_name[0] = '*';
					short_name[1] = '*';
					short_name[2] = '*';
					for(i=3; i<DNS_NAME_LEN; i++){
						short_name[i] = ques[scptr+i];
					}
				}

				qtype = (uint16_t *)++res_ptr;
				res_ptr += 2;
				qclass = (uint16_t *)res_ptr;

				/* Get IP addresses from answers */
				res_ptr += 2;
				for(i=0;i<dns_header->ancount;i++){
					/* skip name */
					res_ptr += 2;
					qtype = (uint16_t *)res_ptr;
					/* skip to data length*/
					res_ptr += 8;
					if(*qtype == T_A){
						dlen = (uint16_t *)res_ptr;
						res_ptr += 2;
						ipaddr = (__be32 *)res_ptr;
						ipkey = *ipaddr;
						BKT_LOCK(ipkey);
						add_dns_rec(ipkey, short_name);
						BKT_UNLOCK(ipkey);
						res_ptr += *dlen;
					} else if(*qtype == T_CNAME){
						dlen = (uint16_t *)res_ptr;
						res_ptr += 2 + *dlen;
					} else{ 
						break;
					}
				}
			}
		}
	}	
	return NF_ACCEPT;
}

int nfl_dns_stat_read( char *page, char **start, off_t off,
					int count, int *eof, void *data )
{
	int len;
	if (off > 0) {
		*eof = 1;
		return 0;
	}
	len = sprintf(page, "# NFL DNS records:%d\n", 
					HASH_COUNT(dnstbl_hhead));
	return len;
}

int init_module()
{
	dnsrec_cache = KMEM_CACHE(dns_record, SLAB_HWCACHE_ALIGN);
	dnsrec_exp_cache = KMEM_CACHE(dns_record_exp, SLAB_HWCACHE_ALIGN);
	export_lhead = kmalloc(sizeof(struct dns_exp_stat), GFP_KERNEL);
	if(!export_lhead){
		printk(KERN_INFO "Cannot allocate memory.\n");
		return -ENOMEM;
	}
	/* Initialize lock */
	export_lock = __SPIN_LOCK_UNLOCKED(export_lock);
	/* First entry in DNS table */
	add_dns_rec(2130706433, "localhost");

	printk(KERN_INFO "Registering DNS Resolver Module...\n");

	INIT_EXP_LHEAD(export_lhead);

	/* Netfilter hook config for NFPROTO_IPV4 */
	/*   NF_IP_LOCAL_IN */
	INIT_NFHO(nfho_ip_in,capture_dnsrec,
			NF_IP_LOCAL_IN,NFPROTO_IPV4,NF_IP_PRI_LAST);

	/* procfs */
	proc_nfl_dns = create_proc_entry("nfl_dns_mod", 0644, NULL);
	if (proc_nfl_dns == NULL) {
		printk(KERN_INFO "Cannot create proc entry for nfl_dns_mod.\n");
		return -ENOMEM;
	} else {
		proc_nfl_dns->proc_fops = &proc_ops;
	}

	proc_nfl_dns_stat = create_proc_entry("nfl_dns_stat", 0644, NULL);
	if (proc_nfl_dns_stat == NULL) {
		printk(KERN_INFO "Cannot create proc entry for nfl_dns_stat.\n");
		return -ENOMEM;
	} else {
		proc_nfl_dns_stat->read_proc = nfl_dns_stat_read;
	}

	return 0;
}

void cleanup_module()
{
	struct dns_record *dnsrec, *tmp_dnsrec;
	struct dns_record_exp *dnsrec_exp, *tmp_dnsrec_exp;

	nf_unregister_hook(&nfho_ip_in);

	/* Free the memory occupied by DNS records */
	HASH_ITER(hh, dnstbl_hhead, dnsrec, tmp_dnsrec) {
		//printk(KERN_INFO "IP: %u.%u.%u.%u -- %s\n", NIPQUAD(&dnsrec->ip), dnsrec->name);	
		HASH_DEL(dnstbl_hhead, dnsrec);
		kmem_cache_free(dnsrec_cache, dnsrec);
	}
	list_for_each_entry_safe(dnsrec_exp, tmp_dnsrec_exp, 
				&(export_lhead->exp_list), exp_list) {
		list_del(&dnsrec_exp->exp_list);
		kmem_cache_free(dnsrec_exp_cache, dnsrec_exp);
	}
	/* Destroy the memory cache */
	kmem_cache_destroy(dnsrec_cache);
	kmem_cache_destroy(dnsrec_exp_cache);
	kfree(export_lhead);
	/* Remove proc file*/
	remove_proc_entry("nfl_dns_mod", NULL);
	remove_proc_entry("nfl_dns_stat", NULL);

	printk(KERN_INFO "Unregistered DNS Resolver Module\n");
}

MODULE_AUTHOR("Xuzi Zhou");
MODULE_DESCRIPTION("Kernel DNS Resolver Module");
MODULE_LICENSE("GPL");