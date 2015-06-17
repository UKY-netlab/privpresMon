/*
 * dns_res.h
 * By Xuzi Zhou
 */

#ifndef TFL_H
#define TFL_H

#include "uthash.h"

/* 
 * IP Hooks
 * NOT for __KERNEL__ in netfilter_ipv4.h 
 */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING       0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN          1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD           2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT         3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING      4
#define NF_IP_NUMHOOKS          5

/*
 * Rules for expiring flows:
 * 1. IDLE_TIMOUT (ms)
 * 2. FORCE_TIMEOUT (ms)
 */

#define DNS_PORT 53
#define DNS_NAME_BUF_LEN 256
#define DNS_NAME_LEN 32
#define DNS_TBL_LIMIT 1000

/*
 * Currently defined opcodes
 */
#define QUERY		0x0		/* standard query */
#define IQUERY		0x1		/* inverse query */
#define STATUS		0x2		/* nameserver status query */
/*#define xxx		0x3		*//* 0x3 reserved */
#define	NS_NOTIFY_OP	0x4		/* notify secondary of SOA change */

/*
 * Currently defined response codes
 */
#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */

#define T_A		1		/* host address */
#define T_CNAME		5

struct dnshdr{
	unsigned	id :16;		/* query identification number */
			/* fields in third byte */
	unsigned	qr: 1;		/* response flag */
	unsigned	opcode: 4;	/* purpose of message */
	unsigned	aa: 1;		/* authoritive answer */
	unsigned	tc: 1;		/* truncated message */
	unsigned	rd: 1;		/* recursion desired */
			/* fields in fourth byte */
	unsigned	ra: 1;		/* recursion available */
	unsigned	pr: 1;		/* primary server req'd (!standard) */
	unsigned	unused :2;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	rcode :4;	/* response code */
			/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
};

struct dns_record{
	__be32 ip;
	char name[DNS_NAME_LEN];
	UT_hash_handle hh;
};

struct dns_record_exp{
	__be32 ip;
	char name[DNS_NAME_LEN];
	/* List head */
	struct list_head exp_list;
};

struct dns_exp_stat{
	uint32_t count;
	/* List head */
	struct list_head exp_list;
};

uint32_t rjen32_hash(__be32 *a);

#define INIT_NFHO(nfho,hook_func,hook_num,proto_f,pri)	\
do{					\
	nfho.hook = hook_func;		\
	nfho.hooknum = hook_num;	\
	nfho.pf = proto_f;		\
	nfho.priority = pri;		\
	nf_register_hook(&nfho);	\
}while(0)

/* ptr version */
#define NIPQUAD(addr)	\
	((unsigned char *)addr)[0],	\
	((unsigned char *)addr)[1],	\
	((unsigned char *)addr)[2],	\
	((unsigned char *)addr)[3]
#endif

#define HASH_RJEN32(key, keylen, num_bkts, hashv, bkt)	\
do{							\
	hashv = rjen32_hash(key);		\
	bkt = hashv & (num_bkts-1);			\
}while(0)

#define BKT_NUM(key) \
	(rjen32_hash(&key) & (dnstbl_hhead->hh.tbl->num_buckets-1))

#define BKT_LOCK(key)	\
do{														\
	spin_lock(												\
			&(dnstbl_hhead->hh.tbl->buckets[BKT_NUM(key)].bkt_lock));	\
}while(0)

#define BKT_UNLOCK(key)	\
do{														\
	spin_unlock(											\
			&(dnstbl_hhead->hh.tbl->buckets[BKT_NUM(key)].bkt_lock));	\
}while(0)

#define INIT_EXP_LHEAD(exp_lhead)	\
do{											\
	exp_lhead->count=0;						\
	INIT_LIST_HEAD(&exp_lhead->exp_list);	\
}while(0)

#define INIT_EXP_ENTRY(dnsrec, dnsrec_exp)	\
do{																	\
	dnsrec_exp = NULL;												\
	dnsrec_exp = kmem_cache_alloc(dnsrec_exp_cache, GFP_KERNEL);	\
	dnsrec_exp->ip = dnsrec->ip;									\
	strncpy(dnsrec_exp->name, dnsrec->name, DNS_NAME_LEN);			\
}while(0)

#define UPDATE_EXPORT_LIST(dnsrec, dnsrec_exp, exp_lhead)	\
do{																	\
	INIT_EXP_ENTRY(dnsrec, dnsrec_exp);								\
	list_add_tail(&(dnsrec_exp->exp_list), &(exp_lhead->exp_list));	\
	exp_lhead->count += 1;									\
}while(0)