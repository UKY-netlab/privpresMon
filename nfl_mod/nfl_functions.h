#ifndef TFL_FUNCTIONS_H
#define TFL_FUNCTIONS_H

#define TIMESTAMP(tv)	\
	tv.tv_sec,	\
	tv.tv_usec

#define TIMESTAMP_TM(broken, tv)	\
	broken.tm_mon+1,		\
	broken.tm_mday,			\
	broken.tm_year+1900,		\
	broken.tm_hour, broken.tm_min,	\
	broken.tm_sec, tv.tv_usec

#define NICMPTC(tc)	\
	((unsigned char *)&tc)[0],	\
	((unsigned char *)&tc)[1]

#define NIPQUAD(addr)	\
	((unsigned char *)&addr)[0],	\
	((unsigned char *)&addr)[1],	\
	((unsigned char *)&addr)[2],	\
	((unsigned char *)&addr)[3]

#define INIT_IPFLOW_STAT(flowstat)	\
do{					\
	flowstat.total_flows=0;		\
	flowstat.total_bytes=0;		\
	flowstat.total_pkts=0;		\
	flowstat.active_flows=0;	\
	flowstat.expired_flows=0;	\
	flowstat.next_seq=0;		\
	flowstat.flowstat_lock = 	\
			__SPIN_LOCK_UNLOCKED(flowstat.flowstat_lock);\
}while(0)

#define INIT_HOST_STAT

#define ASSIGN_FLOWKEY_TCP_UDP(aflowkey, ip_hdr, trans_hdr)	\
do{						\
	aflowkey.protocol = ip_hdr->protocol;	\
	aflowkey.padding1 = 0;				\
	aflowkey.padding2 = 0;				\
	aflowkey.saddr = ip_hdr->saddr;		\
	aflowkey.daddr = ip_hdr->daddr;		\
	aflowkey.sport = trans_hdr->source;	\
	aflowkey.dport = trans_hdr->dest;	\
}while(0)	

#define ASSIGN_FLOWKEY_ICMP(aflowkey, ip_hdr, icmp_hdr)	\
do{								\
	aflowkey.protocol = ip_hdr->protocol;			\
	aflowkey.padding1 = 0;				\
	aflowkey.padding2 = 0;				\
	aflowkey.saddr = ip_hdr->saddr;				\
	aflowkey.daddr = ip_hdr->daddr;				\
	aflowkey.sport = 0;							\
	aflowkey.dport = htons(((__be16)icmp_hdr->type)*256 	\
		+ (__be16)icmp_hdr->code);			\
}while(0)

#define ASSIGN_FLOWKEY_OTHER(aflowkey, ip_hdr)	\
do{												\
	aflowkey.protocol = ip_hdr->protocol;		\
	aflowkey.padding1 = 0;						\
	aflowkey.padding2 = 0;						\
	aflowkey.saddr = ip_hdr->saddr;				\
	aflowkey.daddr = ip_hdr->daddr;				\
	aflowkey.sport = 0;							\
	aflowkey.dport = 0;							\
}while(0)

#define MASK_DNS(aflowkey)	\
do{							\
	if(aflowkey.sport == DNS_PORT && aflowkey.dport != DNS_PORT)\
		aflowkey.dport = dns_mask;								\
	if(aflowkey.dport == DNS_PORT && aflowkey.sport != DNS_PORT)\
		aflowkey.sport = dns_mask;								\
}while(0)

#define INIT_IPFLOW(aflow, aflowkey, flowstat, timev, ip_hdr)	\
do{									\
	aflow->seq = flowstat.next_seq;								\
	aflow->export_count = 0;									\
	aflow->start.tv_sec = timev.tv_sec;							\
	aflow->start.tv_usec = timev.tv_usec;						\
	aflow->intvl_start.tv_sec = timev.tv_sec;					\
	aflow->intvl_start.tv_usec = timev.tv_usec;					\
	aflow->end.tv_sec = timev.tv_sec;							\
	aflow->end.tv_usec = timev.tv_usec;							\
	aflow->pkts = 1;											\
	aflow->intvl_pkts = 1;										\
	aflow->bytes = (uint64_t)ip_hdr->tot_len;					\
	aflow->intvl_bytes = (uint64_t)ip_hdr->tot_len;				\
	aflow->flow_key.protocol = aflowkey.protocol;				\
	aflow->flow_key.padding1 = 0;								\
	aflow->flow_key.padding2 = 0;								\
	aflow->flow_key.saddr = aflowkey.saddr;						\
	aflow->flow_key.daddr = aflowkey.daddr;						\
	aflow->flow_key.sport = aflowkey.sport;						\
	aflow->flow_key.dport = aflowkey.dport;						\
	aflow->flow_lock = __SPIN_LOCK_UNLOCKED(aflow->flow_lock);	\
	SET_IPFLOW_TIMER(aflow->flow_timer);						\
}while(0)

#define SET_IPFLOW_TIMER(atimer)	\
do{									\
	init_timer(&atimer);						\
	atimer.expires = jiffies + msecs_to_jiffies(IDLE_TIMEOUT);	\
	atimer.data = (unsigned long)container_of(			\
			&atimer, struct ipflow, flow_timer);		\
	atimer.function = flow_expire;					\
	add_timer(&atimer);						\
}while(0)

#define ADD_NEW_IPFLOW(aflow, flowhhd, flowstat)		\
do{																		\
	BKT_LOCK(aflow);													\
	HASH_ADD(hh, flowhhd, flow_key, sizeof(struct ipflowkey), aflow);	\
	BKT_UNLOCK(aflow);													\
	spin_lock(&flowstat.flowstat_lock);									\
	flowstat.next_seq += 1;												\
	flowstat.total_flows += 1;											\
	flowstat.active_flows += 1;											\
	spin_unlock(&flowstat.flowstat_lock);								\
}while(0)

#define UPDATE_IPFLOW(aflow)		\
do{														\
	spin_lock(&aflow->flow_lock);						\
	aflow->end.tv_sec = tv.tv_sec;						\
	aflow->end.tv_usec = tv.tv_usec;					\
	aflow->pkts += 1;									\
	aflow->intvl_pkts += 1;								\
	aflow->bytes += (uint64_t)ip_header->tot_len;		\
	aflow->intvl_bytes += (uint64_t)ip_header->tot_len;	\
	mod_timer(&aflow->flow_timer,						\
			jiffies + msecs_to_jiffies(IDLE_TIMEOUT));	\
	spin_unlock(&aflow->flow_lock);						\
}while(0)

#define INIT_EXP_LHEAD(exp_lhead)	\
do{											\
	exp_lhead->expired_count=0;				\
	exp_lhead->active_count=0;				\
	INIT_LIST_HEAD(&exp_lhead->exp_list);	\
}while(0)

#define INIT_EXP_ENTRY(aflow, aflow_exp)	\
do{																	\
	aflow_exp = NULL;												\
	aflow_exp = kmem_cache_alloc(ipflow_exp_cache, GFP_KERNEL);		\
	aflow_exp->flow_key.protocol = aflow->flow_key.protocol;		\
	aflow_exp->flow_key.padding1 = 0;								\
	aflow_exp->flow_key.padding2 = 0;								\
	aflow_exp->flow_key.saddr = aflow->flow_key.saddr;				\
	aflow_exp->flow_key.daddr = aflow->flow_key.daddr;				\
	aflow_exp->flow_key.sport = aflow->flow_key.sport;				\
	aflow_exp->flow_key.dport = aflow->flow_key.dport;				\
	aflow_exp->seq = aflow->seq;									\
	aflow_exp->export_count = aflow->export_count;					\
	aflow_exp->start.tv_sec = aflow->start.tv_sec;					\
	aflow_exp->start.tv_usec = aflow->start.tv_usec;				\
	aflow_exp->intvl_start.tv_sec = aflow->intvl_start.tv_sec;		\
	aflow_exp->intvl_start.tv_usec = aflow->intvl_start.tv_usec;	\
	aflow_exp->end.tv_sec = aflow->end.tv_sec;						\
	aflow_exp->end.tv_usec = aflow->end.tv_usec;					\
	aflow_exp->pkts = aflow->pkts;									\
	aflow_exp->intvl_pkts = aflow->intvl_pkts;						\
	aflow_exp->bytes = aflow->bytes;								\
	aflow_exp->intvl_bytes = aflow->intvl_bytes;					\
}while(0)

#define UPDATE_EXPIRE_LIST(aflow, aflow_exp, exp_lhead)	\
do{																	\
	INIT_EXP_ENTRY(aflow, aflow_exp);								\
	list_add_tail(&(aflow_exp->exp_list), &(exp_lhead->exp_list));	\
	exp_lhead->expired_count += 1;									\
}while(0)

#define UPDATE_EXPORT_LIST(aflow, aflow_exp, exp_lhead, time)	\
do{																	\
	aflow->export_count += 1;										\
	INIT_EXP_ENTRY(aflow, aflow_exp);								\
	list_add_tail(&(aflow_exp->exp_list), &(exp_lhead->exp_list));	\
	RESTART_STAT_INTVL(aflow, time);								\
	exp_lhead->active_count += 1;									\
}while(0)

#define RESTART_STAT_INTVL(aflow, time)		\
do{												\
	aflow->intvl_start.tv_sec = time.tv_sec;	\
	aflow->intvl_start.tv_usec = time.tv_usec;	\
	aflow->intvl_bytes = 0;						\
	aflow->intvl_pkts = 0;						\
}while(0)

#define UPDATE_FLOWSTAT_PKT(iphdr, flowstat)	\
do{														\
	spin_lock(&flowstat.flowstat_lock);					\
	flowstat.total_pkts += 1;							\
	flowstat.total_bytes += (uint64_t)iphdr->tot_len;	\
	spin_unlock(&flowstat.flowstat_lock);				\
}while(0)

#define PRINT_IPFLOW_TCPUDP(aflow, start_tm, end_tm)	\
	printk(KERN_INFO "Flow Seq: %llu\n"		\
		"  Prot: %d  Bytes: %llu  Pkts: %u\n"	\
		"  Start: %d/%d/%ld %d:%d:%d.%ld\n"	\
		"  End: %d/%d/%ld %d:%d:%d.%ld\n"	\
		"  Src:(%u.%u.%u.%u):%d"		\
		"-->Dst:(%u.%u.%u.%u):%d\n"		\
		"-------------------------",		\
		aflow->seq, aflow->flow_key.protocol,	\
		aflow->bytes, aflow->pkts,		\
		TIMESTAMP_TM(start_tm, aflow->start),	\
		TIMESTAMP_TM(end_tm, aflow->end),	\
		NIPQUAD(aflow->flow_key.saddr),		\
		ntohs(aflow->flow_key.sport),		\
		NIPQUAD(aflow->flow_key.daddr),		\
		ntohs(aflow->flow_key.dport))

#define PRINT_IPFLOW_ICMP(aflow)	\
	printk(KERN_INFO "Seq: %llu  Prot: %d  Bytes: %llu  Pkts: %u\n"	\
		"  ICMP type: %u  ICMP code: %u\n"			\
		"  Start: %ld.%06ld  End: %ld.%06ld\n"			\
		"  Src:(%u.%u.%u.%u)-->Dst:(%u.%u.%u.%u)\n"		\
		"-------------------------",				\
		aflow->seq, aflow->flow_key.protocol,			\
		aflow->bytes, aflow->pkts,				\
		NICMPTC(aflow->flow_key.dport),				\
		TIMESTAMP(aflow->start), TIMESTAMP(aflow->end),		\
		NIPQUAD(aflow->flow_key.saddr), 			\
		NIPQUAD(aflow->flow_key.daddr))

#define INIT_NFHO(nfho,hook_func,hook_num,proto_f,pri)	\
do{					\
	nfho.hook = hook_func;		\
	nfho.hooknum = hook_num;	\
	nfho.pf = proto_f;		\
	nfho.priority = pri;		\
	nf_register_hook(&nfho);	\
}while(0)

/*
 * X Macros of customized hash function for uthash
 * LIST_OF_FLOWKEY_FIELDS: iterate fields in struct ipflowkey 
 * HASH_CRC32: uthash style hash function
 */
#define LIST_OF_FLOWKEY_FIELDS	\
	X(__u8, protocol)	\
	X(__be32, saddr)	\
	X(__be32, daddr)	\
	X(__be16, sport)	\
	X(__be16, dport)

#define HASH_CRC32(key, keylen, num_bkts, hashv, bkt)	\
do{							\
	hashv = get_hash_crc32(key);		\
	bkt = hashv & (num_bkts-1);			\
}while(0)

/*
 * Hash table bucket related macros:
 *  1. BKT_NUM(aflow)
 *  2. BKT_LOCK(aflow)
 *  3. BKT_UNLOCK(aflow)
 */
#define BKT_NUM(aflow) \
	(get_hash_crc32(&aflow->flow_key) & (aflow->hh.tbl->num_buckets-1))

#define BKT_LOCK(aflow)	\
do{														\
	spin_lock(												\
			&(aflow->hh.tbl->buckets[BKT_NUM(aflow)].bkt_lock));	\
}while(0)

#define BKT_UNLOCK(aflow)	\
do{														\
	spin_unlock(											\
			&(aflow->hh.tbl->buckets[BKT_NUM(aflow)].bkt_lock));	\
}while(0)

/*
 * Core hash function and hash key comparison function
 *  1. get_hash_crc32()
 *  2. flowkey_cmp()
 */
uint32_t get_hash_crc32(struct ipflowkey *flowkey);
int8_t flowkey_cmp(struct ipflowkey *a, struct ipflowkey *b);

/* get_time_offset(): calcute time diff of two struct timeval variables */
uint32_t get_time_offset(struct timeval sml, struct timeval lrg);

/* Swap pointers of linked lists */
void ptr_swap(struct ipflow_exp_stat **p1, struct ipflow_exp_stat **p2);

/* Change DNS mask port */
int new_dns_mask(int old_mask);

#endif
