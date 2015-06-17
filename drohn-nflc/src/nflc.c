/*
 * nflc.h:
 *  Global variables: database and hashtable headers
 *  main() of nflc
 *
 * By Xuzi Zhou
 */

#include <stdio.h>   
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "nflc.h"
#include "nflc_conf.h"
#include "nflc_utils.h"

/* Debug timer output */
#ifdef NFLC_DEBUG
#define DEBUG_TIMESTAMP(now, word) 	\
do{														\
	printf(word ": %d.%.6d\n", now.tv_sec, now.tv_usec);	\
}while(0)
#endif

/* 
 * Global variables
 */
/* Local network settings */
__be32 lan_addr;
__be32 lan_mask;
__be32 wan_addr;
struct nflc_conf if_conf;
unsigned char wan_mac[6];
unsigned char fid_key[16];
/* Edge statistics */
struct edge_stat estat;
/* Headers of hash tables */
struct dns_record *dns_hhead = NULL;
struct arp_tbl *arp_hhead = NULL;
struct c_flow *cf_hhead = NULL;
struct r_flow *rf_hhead = NULL;
struct lh_stat *lh_hhead = NULL;
struct edge_hash *edges_hhead = NULL;
//struct json_lid_hash *jl_hhead = NULL;
struct json_fid_hash *jf_hhead = NULL;
/* Host ID tracker (LID) */
uint16_t nxt_lid;
/* List for retired fids */
int bglink_count=0;
struct bglink_list *bglink_head = NULL;
struct bglink_list *bglink_tail= NULL;

/*
 * main() of nflc
 */
int main(int argc, char **argv) 
{
	/* FILE pointer to the proc file */
	FILE *fp;
	/* Flow export statistics */
	uint64_t idx, expired, active;
	/* Flow data related */
	char stat_buf[FLOW_STAT_SIZE];
	char entry_buf[FLOW_ENTRY_SIZE];
	char dns_stat_buf[DNS_STAT_SIZE];
	char dns_entry_buf[DNS_ENTRY_SIZE];
	struct ipflow_exp_stat *export_stat;
	struct ipflow_exp *export_entry;
	struct dns_exp_stat *dns_export_stat;
	struct dns_record_exp *dns_export_entry;
	/* Timestamp */
	struct timeval now, pre, start, end;
	int has_new_lids;
	char *nflc_dir = NULL;

	/* Check FID key (retrieve or generate) */
	get_fid_key();

	/* Get options*/
	int c;
	while((c=getopt(argc, argv, "d:")) != -1){
		switch(c){
		/* nflc directory */
		case 'd':
			nflc_dir = optarg;
			break;
		case '?':
			if (optopt == 'd')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		}
	}

	/* Initiate if_conf */
	if_conf.drohn_mtime = 0;
	if_conf.nflc_mtime = 0;
	if_conf.lan_if[0]='\0';
	if_conf.wan_if[0]='\0';
	if_conf.resolve_sites = 0;
	if_conf.use_oui = 1;

	/* nflc runs forever */
	int iter_count = 0;
	while(iter_count < NFLC_TTL){
		iter_count++;
		/* Check directory path input */
		if(dir_check(nflc_dir) != 1){

			fprintf(stderr, "%s is not a valid directory.\n", nflc_dir);
			return 0;
		}

		/* Initialize hash tables */
		has_new_lids = init_lhstat(nflc_dir);
		init_rf(nflc_dir);
		init_arp(nflc_dir);
		init_dns(nflc_dir);
	
		/* Start timer */
		gettimeofday(&now, NULL);
		start = now;
#ifdef NFLC_DEBUG
		DEBUG_TIMESTAMP(now, "START");
#endif

		/* Initialize parameters */
		get_conf();
#ifdef NFLC_DEBUG
		printf("lan: %s  wan: %s\n", if_conf.lan_if, if_conf.wan_if);
		printf("resolve_sites: %d  use_oui: %d\n", if_conf.resolve_sites, if_conf.use_oui);
#endif	
		update_lan_if();
		update_arp();
		INIT_EDGE_STAT(estat);

		/** Read Flow Data **/
		/* Clear buffers for reading file */
		memset(stat_buf, 0, FLOW_STAT_SIZE);
		memset(entry_buf, 0, FLOW_ENTRY_SIZE);
		/* Open proc file */
		if ((fp = fopen(NFL_LOG_FILE,"r")) == NULL){
			die_with_error("Cannot read " NFL_LOG_FILE "!\n");
		}
		/* Prepare LHSTAT table for update */
		refresh_table_lhstat();
		/* Read flow export statistics */
		if(!feof(fp)){
			fread(stat_buf, FLOW_STAT_SIZE, 1, fp);
			export_stat = (struct ipflow_exp_stat *)stat_buf;
			handle_exp_stat(export_stat, &expired, &active);
		}
		idx = 0;
		/* Read flow entries */
		while(!feof(fp)){
			if(fread(entry_buf, FLOW_ENTRY_SIZE, 1, fp)>0
					&& idx<(expired+active)){
				export_entry = (struct ipflow_exp *)entry_buf;
				/* Update tables */
				handle_exp_entry(lan_addr, lan_mask, 
						export_entry, (idx<expired)?0:1);
				idx++;
			}
		} // End of while(!feof(fp))
		fclose(fp);

		// here prepare DNS table & read DNS entries
		/* Clear buffers for reading file */
		memset(dns_stat_buf, 0, DNS_STAT_SIZE);
		memset(dns_entry_buf, 0, DNS_ENTRY_SIZE);
		/* Open proc file */
		if ((fp = fopen(NFL_DNS_FILE,"r")) == NULL){
			die_with_error("Cannot read " NFL_DNS_FILE "!\n");
		}
		/* Get number of DNS entries */
		if(!feof(fp)){
			fread(dns_stat_buf, DNS_STAT_SIZE, 1, fp);
			dns_export_stat = (struct dns_exp_stat *)dns_stat_buf;
		}
		idx = 0;
		/* Read flow entries */
		while(!feof(fp)){
			if(fread(dns_entry_buf, DNS_ENTRY_SIZE, 1, fp)>0
					&& idx<dns_export_stat->count){
				dns_export_entry = (struct dns_record_exp *)dns_entry_buf;
				/* Update DNS table */
				handle_dns_entry(dns_export_entry);
				idx++;
			}
		} // End of while(!feof(fp))
		fclose(fp);
#ifdef NFLC_DEBUG
		printf("ttl  ef#, cf#, proc, eg#, edge_gen, edge_exp, json_gen, "\
				"bk_n_clean_tb, total\n");
		pre = now;
		gettimeofday(&now, NULL);
		//DEBUG_TIMESTAMP(now, "FILE_READ_END");
		printf("tvl %llu, %d, %d", expired+active, HASH_COUNT(cf_hhead),
				time_diff_usec(pre, now));
#endif

		gen_edges();

#ifdef NFLC_DEBUG
		pre = now;
		gettimeofday(&now, NULL);
		//DEBUG_TIMESTAMP(now, "EDGE_EXPORT_END");
		printf(", %d, %d", HASH_COUNT(edges_hhead), time_diff_usec(pre, now));
#endif

		/* Ouput bipartite graph data and update LHSTAT with #hosts info */
		export_edges(nflc_dir, has_new_lids);

#ifdef NFLC_DEBUG
		pre = now;
		gettimeofday(&now, NULL);
		//DEBUG_TIMESTAMP(now, "EDGE_EXPORT_END");
		printf(", %d", time_diff_usec(pre, now));
#endif
		/* Update table: LHSTAT */
		update_dhcp_info();
		update_table_lhstat();
		//output_table_lhstat();
		/* Output json files for dashboard */
		gen_overview_json(nflc_dir);
		gen_avg_overview_json(nflc_dir);
		gen_top_k_json(nflc_dir, 5);

		/* Output timestamp */
		gen_timestamp(nflc_dir, start);

#ifdef NFLC_DEBUG
		pre = now;
		gettimeofday(&now, NULL);
		//DEBUG_TIMESTAMP(now, "EDGE_EXPORT_END");
		printf(", %d", time_diff_usec(pre, now));
#endif
		
		/* Backup data structures */
		backup_rf(nflc_dir);
		backup_lhstat(nflc_dir);
		backup_arp(nflc_dir);
		backup_dns(nflc_dir);

		/* Clean tables */
		clean_edges_hash();
		clean_cf();
		clean_rf();
		clean_lhstat();
		clean_arp();
		clean_dns();

#ifdef NFLC_DEBUG
		pre = now;
		gettimeofday(&now, NULL);
		printf(", %d", time_diff_usec(pre, now));
#endif

		/* End timer */
		gettimeofday(&now, NULL);
		end = now;
#ifdef NFLC_DEBUG
		printf(", %d\n", time_diff_usec(start, end));
		printf("==============================\n");
		fflush(stdout);
#endif	

		/* Wait for the set interval before next round */
		if(iter_count<NFLC_TTL && NFLC_INTVL>(end.tv_sec-start.tv_sec)){
			sleep(NFLC_INTVL-(end.tv_sec-start.tv_sec));
		}
	}// End of while(1)
	if(NFLC_LAST_INTVL>(end.tv_sec-start.tv_sec)){
		sleep(NFLC_LAST_INTVL-(end.tv_sec-start.tv_sec));
	}

	return 0;
}