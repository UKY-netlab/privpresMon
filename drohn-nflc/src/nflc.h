/*
 * nflc.h
 *
 * By Xuzi Zhou
 */
#ifndef NFLC_H
#define NFLC_H

#include <linux/types.h>
#include <stdlib.h>
#include <stdint.h>
#include "uthash.h"

#define NFL_LOG_FILE "/proc/nfl_mod"
#define NFL_DNS_FILE "/proc/nfl_dns_mod"
#define ARP_FILE "/proc/net/arp"
#define DROHN_ID_FILE "/etc/drohn/ID"
#define DROHN_FID_KEY_FILE "/etc/drohn/FIDK"
#define DHCP_LEASE_FILE "/tmp/dhcp.leases"

#define UPLOAD_DIR_NAME "upload"
#define UPLOAD_TMP_DIR_NAME "upload_tmp"

#define NFLC_RF_FILE "rf.nfl"
#define NFLC_LHSTAT_FILE "lhstat.nfl"
#define NFLC_ARP_FILE "arp.nfl"
#define NFLC_DNS_FILE "dns.nfl"
#define HITCOUNT_FILE "dashboard_hit_count"
#define HITCOUNT_TMP_FILE "tmp_dashboard_hit_count"
#define EDGE_OUTPUT_PREFIX "wildcat_"

#define TIMESTAMP_FILE "timestamp"

#define JSON_HOSTS_FILE "01_current_hosts.json"
#define JSON_FLOWS_FILE "02_current_flows.json"
#define JSON_FLOWS_L2F_FILE "05_current_flows_l2f.json"
#define JSON_FLOWS_F2L_FILE "08_current_flows_f2l.json"
#define JSON_PKTS_FILE "03_current_pkts.json"
#define JSON_PKTS_L2F_FILE "06_current_pkts_l2f.json"
#define JSON_PKTS_F2L_FILE "09_current_pkts_f2l.json"
#define JSON_BYTES_FILE "04_current_bytes.json"
#define JSON_BYTES_L2F_FILE "07_current_bytes_l2f.json"
#define JSON_BYTES_F2L_FILE "10_current_bytes_f2l.json"

#define JSON_AVG_HOSTS_FILE "01_avg_hosts.json"
#define JSON_AVG_FLOWS_FILE "02_avg_flows.json"
#define JSON_AVG_FLOWS_L2F_FILE "05_avg_flows_l2f.json"
#define JSON_AVG_FLOWS_F2L_FILE "08_avg_flows_f2l.json"
#define JSON_AVG_PKTS_FILE "03_avg_pkts.json"
#define JSON_AVG_PKTS_L2F_FILE "06_avg_pkts_l2f.json"
#define JSON_AVG_PKTS_F2L_FILE "09_avg_pkts_f2l.json"
#define JSON_AVG_BYTES_FILE "04_avg_bytes.json"
#define JSON_AVG_BYTES_L2F_FILE "07_avg_bytes_l2f.json"
#define JSON_AVG_BYTES_F2L_FILE "10_avg_bytes_f2l.json"

#define JSON_FDEG_FILE "02_topk_fdeg.json"
#define JSON_PDEG_FILE "03_topk_pdeg.json"
#define JSON_BDEG_FILE "04_topk_bdeg.json"
#define JSON_FDEG_L2F_FILE "05_topk_fdeg_l2f.json"
#define JSON_PDEG_L2F_FILE "06_topk_pdeg_l2f.json"
#define JSON_BDEG_L2F_FILE "07_topk_bdeg_l2f.json"
#define JSON_FDEG_F2L_FILE "08_topk_fdeg_f2l.json"
#define JSON_PDEG_F2L_FILE "09_topk_pdeg_f2l.json"
#define JSON_BDEG_F2L_FILE "10_topk_bdeg_f2l.json"

#define WAN_ADDR_ID 0xFFFF

#define FLOW_STAT_SIZE sizeof(struct ipflow_exp_stat)
#define FLOW_ENTRY_SIZE sizeof(struct ipflow_exp)
#define DNS_STAT_SIZE sizeof(struct dns_exp_stat)
#define DNS_ENTRY_SIZE sizeof(struct dns_record_exp)
#define DNS_REC_SIZE sizeof(struct dns_record)
#define DNS_EXP_SIZE sizeof(struct dns_tbl_exp)
#define EDGE_EXP_SIZE sizeof(struct edge_export)
#define RF_SIZE sizeof(struct r_flow)
#define RF_EXP_SIZE sizeof(struct r_flow_exp)
#define EF_SIZE sizeof(struct e_flow)
#define EF_EXP_SIZE sizeof(struct e_flow_exp)
#define LH_STAT_SIZE sizeof(struct lh_stat)
#define LH_STAT_EXP_SIZE sizeof(struct lh_stat_exp)
#define ARP_SIZE sizeof(struct arp_tbl)
#define ARP_EXP_SIZE sizeof(struct arp_tbl_exp)
#define MH_SIZE sizeof(struct magic_head)

#define DROHN_ID_LEN 12
#define FID_KEY_LEN 16
#define FID_LEN 23
#define HOST_NAME_LEN 24
#define DNS_NAME_LEN 32
#define MAX_FILE_NAME_LEN 150
#define NFLC_INTVL 300  //5 minutes in seconds
#define NFLC_LAST_INTVL 260
#define NFLC_TTL 288  //# of intervals in 24hr
#define RE_DUR 1800  //30 minutes in seconds
#define DNS_TTL 288  //# of intervals in 24hr
#define RF_TBL_LIMIT 24000
#define RF_TBL_THR 16000
#define DNS_TBL_LIMIT 8000 
#define DNS_TBL_THR 6000
#define BPS_UNIT 1000	//1 millisecond in microseconds
#define EWMA_ALPHA 0.1
#define EWMA_ALPHA_COMP 0.9
#define PORT_LVL0 65536
#define PORT_LVL1 256
#define PORT_LVL2 16
#define PORT_LVL_R 16

/******
 * Flow export related
 ******/
struct list_head {
	struct list_head *next, *prev;
};
/* Flow export statistics */
struct ipflow_exp_stat {
	uint64_t expired_count;
	uint64_t active_count;
	/* Linux list head */
	struct list_head exp_list;
};
/* Flow key */
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
/* Flow export entry */
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

/******
 * DNS table related structs 
 ******/
struct dns_record{
	__be32 ip;
	uint32_t ttl;
	uint32_t id;
	char name[DNS_NAME_LEN];
	UT_hash_handle hh;
};

struct dns_tbl_exp{
	__be32 ip;
	uint32_t ttl;
	char name[DNS_NAME_LEN];
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

/******
 * Hash table entry of cf (current flows)
 ******/
struct c_flow {
	uint64_t seq;
	/* Flow identifications */
	struct ipflowkey flow_key;
	uint32_t export_count;
	struct timeval start;
	struct timeval intvl_start;
	struct timeval end;
	/* Flow statistics */
	uint32_t pkts;
	uint32_t intvl_pkts;
	uint64_t bytes;
	uint64_t intvl_bytes;
	/* Hash table handler */
	UT_hash_handle hh;
};

/******
 * Hash table entry of rf (recent flows)
 ******/
struct r_flow {
	uint64_t seq;
	/* Flow identifications */
	struct ipflowkey flow_key;
	uint16_t is_active;
	uint32_t export_count;
	struct timeval start;
	struct timeval end;
	/* Flow statistics */
	uint32_t pkts;
	uint64_t bytes;
	/* Hash table handler */
	UT_hash_handle hh;
};
struct r_flow_exp {
	uint64_t seq;
	/* Flow identifications */
	struct ipflowkey flow_key;
	uint16_t is_active;
	uint32_t export_count;
	struct timeval start;
	struct timeval end;
	/* Flow statistics */
	uint32_t pkts;
	uint64_t bytes;
};

/******
 * Hash table entry of ARPTBL
 ******/
struct arp_tbl {
	__be32 addr;	// Hash table key
	unsigned char lh_mac[6];
	UT_hash_handle hh;
};
struct arp_tbl_exp {
	__be32 addr;
	unsigned char lh_mac[6];
};

/******
 * Hash table entry of LHSTAT
 ******/
struct lh_stat {
	unsigned char lh_mac[6];	// Hash table key
	uint16_t lid;		// Local host ID
	__be32 c_ip;		// Current IP address
	char host_name[HOST_NAME_LEN+1];
	/* Current statistics (prefix: c_) */
	uint32_t c_hosts;
	uint32_t c_flows_l2f;
	uint32_t c_flows_f2l;
	uint32_t c_pkts_l2f;
	uint32_t c_pkts_f2l;
	uint64_t c_bytes_l2f;
	uint64_t c_bytes_f2l;
	/* Current interval statistics (prefix: ci_) */
	uint32_t ci_hosts;
	uint32_t ci_flows_l2f;
	uint32_t ci_flows_f2l;
	uint32_t ci_pkts_l2f;
	uint32_t ci_pkts_f2l;
	uint64_t ci_bytes_l2f;
	uint64_t ci_bytes_f2l;
	/* Lifetime EWMA (prefix: a_) */
	double a_hosts;
	double a_flows_l2f;
	double a_flows_f2l;
	double a_pkts_l2f;
	double a_pkts_f2l;
	uint64_t a_bytes_l2f;
	uint64_t a_bytes_f2l;
	/* Lifetime interval EWMA (prefix: ai_) */
	double ai_hosts;
	double ai_flows_l2f;
	double ai_flows_f2l;
	double ai_pkts_l2f;
	double ai_pkts_f2l;
	uint64_t ai_bytes_l2f;
	uint64_t ai_bytes_f2l;
	/* Lifetime statistics */
	uint64_t flows_l2f;
	uint64_t flows_f2l;
	uint64_t pkts_l2f;
	uint64_t pkts_f2l;
	uint64_t bytes_l2f;
	uint64_t bytes_f2l;
	UT_hash_handle hh;
};
struct lh_stat_exp {
	unsigned char lh_mac[6];	// Hash table key
	uint16_t lid;		// Local host ID
	__be32 c_ip;		// Current IP address
	char host_name[HOST_NAME_LEN+1];
	/* Current statistics (prefix: c_) */
	uint32_t c_hosts;
	uint32_t c_flows_l2f;
	uint32_t c_flows_f2l;
	uint32_t c_pkts_l2f;
	uint32_t c_pkts_f2l;
	uint64_t c_bytes_l2f;
	uint64_t c_bytes_f2l;
	/* Current interval statistics (prefix: c_) */
	uint32_t ci_hosts;
	uint32_t ci_flows_l2f;
	uint32_t ci_flows_f2l;
	uint32_t ci_pkts_l2f;
	uint32_t ci_pkts_f2l;
	uint64_t ci_bytes_l2f;
	uint64_t ci_bytes_f2l;
	/* Lifetime EWMA (prefix: a_) */
	double a_hosts;
	double a_flows_l2f;
	double a_flows_f2l;
	double a_pkts_l2f;
	double a_pkts_f2l;
	uint64_t a_bytes_l2f;
	uint64_t a_bytes_f2l;
	/* Lifetime interval EWMA (prefix: ai_) */
	double ai_hosts;
	double ai_flows_l2f;
	double ai_flows_f2l;
	double ai_pkts_l2f;
	double ai_pkts_f2l;
	uint64_t ai_bytes_l2f;
	uint64_t ai_bytes_f2l;
	/* Lifetime statistics */
	uint64_t flows_l2f;
	uint64_t flows_f2l;
	uint64_t pkts_l2f;
	uint64_t pkts_f2l;
	uint64_t bytes_l2f;
	uint64_t bytes_f2l;
};

/******
 * Hashtable output magic head
 ******/
struct magic_head{
	char magic_word[4];
	uint32_t entry_count;
};

/****** 
 * Bipartite graph related data structures 
 ******/
/* Hash table entry related */
struct top_port {
	uint16_t port;
	uint16_t cnt;
};
struct edge_hash_key {
	unsigned char lh_mac[6];
	__be32 faddr;
};
struct edge_hash {
	struct edge_hash_key edge_key;	// Hash table key
	uint8_t prot_bitmap;
	struct top_port ports[3];
	uint32_t max_dur;
	uint32_t flows_l2f;
	uint32_t flows_f2l;
	uint32_t intvl_flows_l2f;
	uint32_t intvl_flows_f2l;
	uint32_t pkts_l2f;
	uint32_t pkts_f2l;
	uint32_t intvl_pkts_l2f;
	uint32_t intvl_pkts_f2l;
	uint64_t bytes_l2f;
	uint64_t bytes_f2l;
	uint64_t intvl_bytes_l2f;
	uint64_t intvl_bytes_f2l;
	UT_hash_handle hh;
};
/* Graph output related */
struct edge_stat {
	uint32_t edges_total;
	uint32_t flows_total;
	uint32_t intvl_flows_total;
	uint32_t flows_l2f;
	uint32_t flows_f2l;
	uint32_t intvl_flows_l2f;
	uint32_t intvl_flows_f2l;
	uint32_t pkts_l2f;
	uint32_t pkts_f2l;
	uint32_t intvl_pkts_l2f;
	uint32_t intvl_pkts_f2l;
	uint64_t bytes_l2f;
	uint64_t bytes_f2l;
	uint64_t intvl_bytes_l2f;
	uint64_t intvl_bytes_f2l;
};

/***********
 * structs for JSON output
 ***********/
 /*
struct json_lid_hash {
	uint16_t lid;	// Hash table key
	uint16_t idx;
	UT_hash_handle hh;
};
struct json_fid_hash {
	uint32_t fid;	// Hash table key
	uint16_t idx;
	UT_hash_handle hh;
};*/
struct json_fid_hash {
	__be32 faddr;		// Hash table key
	int node_idx;
	UT_hash_handle hh;
};

/*
 * List for temporarily storing BG links
 */
struct bglink_list {
    int v_src;
    int v_tgt;
    uint64_t v_val;
    struct bglink_list *next;
};

/******
 * Macros
 ******/
#define NICMPTC(tc)	\
	((unsigned char *)&tc)[0],	\
	((unsigned char *)&tc)[1]

#define NIPQUAD(addr)	\
	((unsigned char *)&addr)[0],	\
	((unsigned char *)&addr)[1],	\
	((unsigned char *)&addr)[2],	\
	((unsigned char *)&addr)[3]

#define INIT_EDGE_STAT(estat)	\
do{								\
	estat.edges_total = 0;		\
	estat.flows_total = 0;		\
	estat.intvl_flows_total = 0;\
	estat.flows_l2f = 0;		\
	estat.flows_f2l = 0;		\
	estat.intvl_flows_l2f = 0;	\
	estat.intvl_flows_f2l = 0;	\
	estat.pkts_l2f = 0;			\
	estat.pkts_f2l = 0;			\
	estat.intvl_pkts_l2f = 0;	\
	estat.intvl_pkts_f2l = 0;	\
	estat.bytes_l2f = 0;		\
	estat.bytes_f2l = 0;		\
	estat.intvl_bytes_l2f = 0;	\
	estat.intvl_bytes_f2l = 0;	\
}while(0)

#endif
