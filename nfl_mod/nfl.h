/*
 * nfl.h
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
#ifdef NFL_DEBUG
#define IDLE_TIMEOUT 30000
#define FORCE_TIMEOUT 60000*5
#else
#define IDLE_TIMEOUT 60000*5
#define FORCE_TIMEOUT 60000*15
#endif

#define NSEC_IN_A_MSEC 1000

#define MAX_FLOW_TABLE_SIZE 20000
#define MAX_EXPIRE_LIST_SIZE 12000
#define EXPIRE_LIST_THR 1000

#define DNS_PORT 53
#define DNS_MASK_PORT_START 50000
#define DNS_MASK_PORT_END 51000

struct ipflowstat {
	/* Overall statistics*/
	uint64_t total_flows;
	uint64_t total_bytes;
	uint64_t total_pkts;
	uint64_t active_flows;
	uint64_t expired_flows;
	uint64_t next_seq;
	/* Spinlock */
	spinlock_t flowstat_lock;
};

/*
 * Data structures of individual flows:
 *  struct ipflowkey
 *  struct ipflow
 */
struct ipflowkey {
	/* Flow key parameters */
	__u8 protocol;
	uint8_t padding1;
	uint16_t padding2;
	__be16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct ipflow {
	struct ipflowkey flow_key;
	/* Flow identifications */
	uint64_t seq;
	uint32_t export_count;
	struct timeval start;
	struct timeval intvl_start;
	struct timeval end;
	/* Flow statistics */
	uint32_t pkts;
	uint32_t intvl_pkts;
	uint64_t bytes;
	uint64_t intvl_bytes;
	/* Timer */
	struct timer_list flow_timer;
	/* Spinlock */
	spinlock_t flow_lock;
	/* hash table handler */
	UT_hash_handle hh;
};

/* 
 * Flow record structures for expired IP flows:
 *  struct ipflow_exp_stat
 *  struct ipflow_exp
 */
struct ipflow_exp_stat {
	uint64_t expired_count;
	uint64_t active_count;
	/* List head */
	struct list_head exp_list;
};

struct ipflow_exp {
	struct ipflowkey flow_key;
	/* Flow identifications */
	uint64_t seq;
	uint32_t export_count;
	struct timeval start;
	struct timeval intvl_start;
	struct timeval end;
	/* Flow statistics */
	uint32_t pkts;
	uint32_t intvl_pkts;
	uint64_t bytes;
	uint64_t intvl_bytes;
	/* List head */
	struct list_head exp_list;
};

#endif
