/*
 * nflc_utils.c:
 *   nflc utilities
 *
 * By Xuzi Zhou
 */

#include <linux/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "nflc_conf.h"
#include "nflc_utils.h"

/* Global variables */
static char fid_b64_table[] = {'0','1','2','3','4','5','6','7','8','9',
                                'a','b','c','d','e','f','g','h','i','j',
                                'k','l','m','n','o','p','q','r','s','t', 
                                'u','v','w','x','y','z','A','B','C','D',
                                'E','F','G','H','I','J','K','L','M','N',
                                'O','P','Q','R','S','T','U','V','W','X',
                                'Y','Z','+','/'};

extern __be32 lan_addr;
extern __be32 lan_mask;
extern __be32 wan_addr;
extern struct nflc_conf if_conf;
extern unsigned char wan_mac[6];
extern unsigned char fid_key[16];
extern struct edge_stat estat;
extern struct dns_record *dns_hhead;
extern struct arp_tbl *arp_hhead;
extern struct c_flow *cf_hhead;
extern struct r_flow *rf_hhead;
extern struct lh_stat *lh_hhead;
extern struct edge_hash *edges_hhead;
//extern struct json_lid_hash *jl_hhead;
extern struct json_fid_hash *jf_hhead;
extern uint16_t nxt_lid;
extern int bglink_count;
extern struct bglink_list *bglink_head;
extern struct bglink_list *bglink_tail;


int32_t time_diff_sec(struct timeval start, struct timeval end)
{
	return (end.tv_sec-start.tv_sec);
}

int32_t time_diff_msec(struct timeval start, struct timeval end)
{
	return ((end.tv_sec-start.tv_sec)*1000
			+(end.tv_usec-start.tv_usec)/1000);
}

int32_t time_diff_usec(struct timeval start, struct timeval end)
{
	return ((end.tv_sec-start.tv_sec)*1000000
			+(end.tv_usec-start.tv_usec));
}

void swap(uint16_t *a, uint16_t *b) {
   uint16_t t = *a;
   *a = *b;
   *b = t;
}

double stat_per_interval(uint32_t value, int32_t dur)
{
	if(dur < BPS_UNIT)
		dur = BPS_UNIT;
	return ((double)value/dur)*1000000;
}

void die_with_error(const char *msg) {
	perror(msg);
	exit(1);
}

void handle_crypto_error(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

unsigned char * encfid_b64(unsigned char *encfid)
{
	unsigned char *buf;
	unsigned char *ret;
	int times = 5;
	int i,cur;
	int j = 0;

	buf = encfid;
	ret=(unsigned char *)malloc(22);

	/* First 120 bits */
	for(i=0; i<times; i++){
		cur = (buf[0]&0xFC)>>2;
		ret[j++] = fid_b64_table[cur];
		cur = ((buf[0]&0x03)<<4)+((buf[1]&0xF0)>>4);
		ret[j++] = fid_b64_table[cur];
		cur = ((buf[1]&0x0F)<<2)+((buf[2]&0xC0)>>6);
		ret[j++] = fid_b64_table[cur];
		cur = buf[2]&0x3F;
		ret[j++] = fid_b64_table[cur];
		buf += 3;
	}
	/* Last 8 bits */
	cur = (buf[0]&0xFC)>>2;
	ret[j++] = fid_b64_table[cur];
	cur = buf[0]&0x03;
	ret[j++] = fid_b64_table[cur];
	ret[j] = '\0';

	return ret;
}

int dir_check(char *drohn_dir)
{
	struct stat s;
	int err = stat(drohn_dir, &s);
	if(err == -1) {
    	return -1;
	}
	else {
    	if(S_ISDIR(s.st_mode)) {
        	/* it's a dir */
        	return 1;
    	}
    	else {
        	/* exists but is no dir */
        	return 0;
    	}
	}
}

/*
 * Retrieve or generate AES key for FIDs 
 */
void get_fid_key()
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	int need_key = 0;
	FILE *fp, *fp_devrand;
	char file_path[MAX_FILE_NAME_LEN];
	int i;

	snprintf(file_path, sizeof(file_path), DROHN_FID_KEY_FILE);

	/* Retrieve key from file */
	if ((fp = fopen(file_path,"r")) != NULL){
		need_key = fread(fid_key, sizeof(fid_key), 1, fp);
		fclose(fp);
	}
	/* Generate new key */
	if(!need_key) {
		/* Randomly generate from /dev/random */
		if((fp_devrand = fopen("/dev/random", "r")) != NULL){
			fread(fid_key, sizeof(fid_key), 1, fp_devrand);
			/* Backup to file */
			fp = fopen(file_path, "wb");
			fwrite(fid_key, sizeof(fid_key), 1, fp);
			fclose(fp);

			fclose(fp_devrand);
		} else {
			fprintf(stderr, "Cannot open /dev/random !!!\n");
		}
	}
}

int maccmp(unsigned char *a, unsigned char *b, int len)
{
	int i;
	for(i=0;i<len;i++){
		if(a[i]<b[i])
			return 1;
		if(a[i]>b[i])
			return -1;
	}
	return 0;
}
/* Network related functions:
 * update_lan_if(): get LAN IP address and LAN netmask
 * addr_is_local(): return 1 for local address, otherwise 0
 * addr_is_special(): return 1 for broadcast address, otherwise 0
 */
void update_lan_if()
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	int fd;
	struct ifreq ifr_lan, ifr_wan, ifr_wan_hw;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	/* Get an IPv4 IP address */
	ifr_lan.ifr_addr.sa_family = AF_INET;

	/* Address attached to LAN interface */
	strncpy(ifr_lan.ifr_name, if_conf.lan_if, IFNAMSIZ-1);

	/* LAN IP Address */
	ioctl(fd, SIOCGIFADDR, &ifr_lan);
	lan_addr = ((struct sockaddr_in *)&ifr_lan.ifr_addr)->sin_addr.s_addr;
	/* LAN Netmask*/
	ioctl(fd, SIOCGIFNETMASK, &ifr_lan);
	lan_mask = ((struct sockaddr_in *)&ifr_lan.ifr_addr)->sin_addr.s_addr;

	/* Address attached to WAN interface */
	strncpy(ifr_wan.ifr_name, if_conf.wan_if, IFNAMSIZ-1);

	/* WAN IP Address */
	ioctl(fd, SIOCGIFADDR, &ifr_wan);
	wan_addr = ((struct sockaddr_in *)&ifr_wan.ifr_addr)->sin_addr.s_addr;

	/* Address attached to WAN interface */
	strncpy(ifr_wan_hw.ifr_name, if_conf.wan_if, IFNAMSIZ-1);
	/* WAN MAC Address */
	ioctl(fd, SIOCGIFHWADDR, &ifr_wan_hw);
	COPY_MAC(wan_mac, ifr_wan_hw.ifr_hwaddr.sa_data);

	close(fd);
}
int addr_is_local(__be32 addr)
{
	__be32 masked = (addr & lan_mask);
	__be32 lan = (lan_addr & lan_mask);
	if(addr == wan_addr || masked == lan){
		return 1;
	}
	else{
		return 0;
	}
}
int addr_is_special(__be32 addr)
{
	__be32 inv_mask = ~ lan_mask;
	__be32 lb = htonl(0x7F000000);  //127.0.0.0
	__be32 lb_mask = htonl(0xFF000000);  //255.0.0.0
	__be32 mc = htonl(0xE0000000);  //224.0.0.0
	__be32 mc_mask = htonl(0xF0000000);  //240.0.0.0
	if(addr == htonl(0xFFFFFFFF)  //255.255.255.255
		|| addr == (lan_addr | inv_mask)  //local broadcast addr
		|| (addr & mc_mask) == mc  //multicast
		|| (addr & lb_mask) == lb){ //loopback
		return 1;
	}
	else{
		return 0;
	}
}

uint16_t gen_lid(__be32 addr)
{
	if(addr == wan_addr){
		return WAN_ADDR_ID;
	}
	else{
		return nxt_lid++;
	}
}

/* Update ARP table */
void create_arp_entry(struct arp_tbl *tmp_arp_entry)
{
	struct arp_tbl *arp_entry;
	arp_entry = malloc(sizeof(struct arp_tbl));
	COPY_ARP_FIELDS(arp_entry, tmp_arp_entry);
	HASH_ADD(hh, arp_hhead, addr, sizeof(__be32), arp_entry);
}
void create_wan_arp_entry()
{
	struct arp_tbl *arp_entry, *tmp_arp;
	arp_entry = malloc(sizeof(struct arp_tbl));
	arp_entry->addr = wan_addr;
	COPY_MAC(arp_entry->lh_mac, wan_mac);
	HASH_FIND(hh, arp_hhead, &(arp_entry->addr), 
				sizeof(__be32), tmp_arp);
	if(tmp_arp == NULL){
		HASH_ADD(hh, arp_hhead, addr, 
					sizeof(__be32), arp_entry);
	} else {
		free(arp_entry);
	}
}
void update_arp()
{
	//printf("S %s\n", __FUNCTION__);
	FILE *fp;
	struct arp_tbl *arp_entry, *tmp_arp;;
	struct in_addr ip;

	/* 1/2: from ARP table */
	if ((fp = fopen(ARP_FILE, "r"))!= NULL){
		char buf[512], *ptr, *tmp, *tok;
		arp_entry = malloc(sizeof(struct arp_tbl));
		/* skip header line */
		ptr = fgets(buf, sizeof(buf), fp);
		/* IP address | HW type | Flags | HW address | Mask | Device */
		while ((ptr = fgets(buf, sizeof(buf), fp)))
		{
			tmp = strdup(ptr);
			/* IP address */
			tok = strsep(&tmp, " ");
			inet_aton(tok, &ip);
			arp_entry->addr = ip.s_addr;
			/* HW type: skip */
			do{
				tok = strsep(&tmp, " ");
			}while (strcmp (tok,"")== 0);
			/* Flags: skip */
			do{
				tok = strsep(&tmp, " ");
			}while (strcmp (tok,"")== 0);
			/* HW address and skip Mask & Device */
			do{
				tok = strsep(&tmp, " ");
			}while (strcmp (tok,"")== 0);
			sscanf(tok, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
					&arp_entry->lh_mac[0], &arp_entry->lh_mac[1], 
					&arp_entry->lh_mac[2], &arp_entry->lh_mac[3], 
					&arp_entry->lh_mac[4], &arp_entry->lh_mac[5]);

			/* Populate ARP hash table */
			HASH_FIND(hh, arp_hhead, &(arp_entry->addr), 
				sizeof(__be32), tmp_arp);
			if(tmp_arp == NULL){
				create_arp_entry(arp_entry);
			}
			else{
				COPY_MAC(tmp_arp->lh_mac, arp_entry->lh_mac);
			}
		}
		free(arp_entry);
		fclose(fp);
	}
	/* 2/2: Add WAN MAC addr entry */
	create_wan_arp_entry();
}

void update_dhcp_info()
{
	//printf("S %s\n", __FUNCTION__);
	FILE *fp;
	unsigned char tmp_mac[6];
	struct lh_stat *lh_entry;

	if ((fp = fopen(DHCP_LEASE_FILE, "r"))!= NULL){
		char buf[512], *ptr, *tmp, *tok;

		/* Expire Time | MAC | IP | Host Name | Client ID */
		while ((ptr = fgets(buf, sizeof(buf), fp)))
		{
			tmp = strdup(ptr);
			/* Expire Time: skip */
			tok = strsep(&tmp, " ");
			/* HW address */
			tok = strsep(&tmp, " ");
			sscanf(tok, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
					&tmp_mac[0], &tmp_mac[1], &tmp_mac[2], 
					&tmp_mac[3], &tmp_mac[4], &tmp_mac[5]);
			/* IP: skip*/
			tok = strsep(&tmp, " ");
			/* Host Name */
			tok = strsep(&tmp, " ");
			/* Search LHSTAT table */
			HASH_FIND(hh, lh_hhead, &tmp_mac, 6, lh_entry);
			if(lh_entry != NULL){
				strncpy(lh_entry->host_name, tok, HOST_NAME_LEN);
				if(lh_entry->host_name[HOST_NAME_LEN-1] != '\0' 
					&& lh_entry->host_name[HOST_NAME_LEN-2] != '\0' 
					&& lh_entry->host_name[HOST_NAME_LEN-3] != '\0'){
					lh_entry->host_name[HOST_NAME_LEN-1] = '.';
					lh_entry->host_name[HOST_NAME_LEN-2] = '.';
					lh_entry->host_name[HOST_NAME_LEN-3] = '.';
					lh_entry->host_name[HOST_NAME_LEN] = '\0';
				}
			}
		}
		fclose(fp);
	}
}

int cf_sort_addr(struct c_flow *a, struct c_flow *b)
{
	__be32 as=a->flow_key.saddr;
	__be32 ad=a->flow_key.daddr;
	__be32 asmall=(as<ad?as:ad);
	__be32 bs=b->flow_key.saddr;
	__be32 bd=b->flow_key.daddr;
	__be32 bsmall=(bs<bd?bs:bd);
	if(as+ad<bs+bd) return -1;
	else if(as+ad==bs+bd){
		if(asmall<bsmall) return -1;
		else if(asmall==bsmall) return 0;
		else return 1;
	}
	else return 1;
}

/* Hash table sort function (in addr order) */
int lhstat_sort_lid(struct lh_stat *a, struct lh_stat *b)
{
	if(a->lid < b->lid){
		return -1;
	}
	else if(a->lid == b->lid){
		return 0;
	}
	else{
		return 1;
	}
}

int edge_sort_addr(struct edge_hash *a, struct edge_hash *b)
{
	return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
}

/* Hash table sort function (in degree order) */
/* with flow-lifetime data */
int edge_sort_p_fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->flows_l2f+a->flows_f2l
			< b->flows_l2f+b->flows_f2l){
		return 1;
	}
	else if(a->flows_l2f+a->flows_f2l 
			== b->flows_l2f+b->flows_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_pdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->pkts_l2f+a->pkts_f2l
			< b->pkts_l2f+b->pkts_f2l){
		return 1;
	}
	else if(a->pkts_l2f+a->pkts_f2l 
			== b->pkts_l2f+b->pkts_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_bdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->bytes_l2f+a->bytes_f2l
			< b->bytes_l2f+b->bytes_f2l){
		return 1;
	}
	else if(a->bytes_l2f+a->bytes_f2l 
			== b->bytes_l2f+b->bytes_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_fl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->flows_l2f < b->flows_l2f){
		return 1;
	}
	else if(a->flows_l2f == b->flows_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_pl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->pkts_l2f < b->pkts_l2f){
		return 1;
	}
	else if(a->pkts_l2f == b->pkts_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_bl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->bytes_l2f < b->bytes_l2f){
		return 1;
	}
	else if(a->bytes_l2f == b->bytes_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_ff2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->flows_f2l < b->flows_f2l){
		return 1;
	}
	else if(a->flows_f2l == b->flows_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_pf2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->pkts_f2l < b->pkts_f2l){
		return 1;
	}
	else if(a->pkts_f2l == b->pkts_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_p_bf2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->bytes_f2l < b->bytes_f2l){
		return 1;
	}
	else if(a->bytes_f2l == b->bytes_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
/* with flow-current-interval data */
int edge_sort_fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_flows_l2f+a->intvl_flows_f2l
			< b->intvl_flows_l2f+b->intvl_flows_f2l){
		return 1;
	}
	else if(a->intvl_flows_l2f+a->intvl_flows_f2l 
			== b->intvl_flows_l2f+b->intvl_flows_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_pdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_pkts_l2f+a->intvl_pkts_f2l
			< b->intvl_pkts_l2f+b->intvl_pkts_f2l){
		return 1;
	}
	else if(a->intvl_pkts_l2f+a->intvl_pkts_f2l 
			== b->intvl_pkts_l2f+b->intvl_pkts_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_bdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_bytes_l2f+a->intvl_bytes_f2l
			< b->intvl_bytes_l2f+b->intvl_bytes_f2l){
		return 1;
	}
	else if(a->intvl_bytes_l2f+a->intvl_bytes_f2l 
			== b->intvl_bytes_l2f+b->intvl_bytes_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_fl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_flows_l2f < b->intvl_flows_l2f){
		return 1;
	}
	else if(a->intvl_flows_l2f == b->intvl_flows_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_pl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_pkts_l2f < b->intvl_pkts_l2f){
		return 1;
	}
	else if(a->intvl_pkts_l2f == b->intvl_pkts_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_bl2fdeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->intvl_bytes_l2f < b->intvl_bytes_l2f){
		return 1;
	}
	else if(a->intvl_bytes_l2f == b->intvl_bytes_l2f){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_ff2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->flows_f2l < b->flows_f2l){
		return 1;
	}
	else if(a->flows_f2l == b->flows_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_pf2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->pkts_f2l < b->pkts_f2l){
		return 1;
	}
	else if(a->pkts_f2l == b->pkts_f2l){
		return 0;
	}
	else{
		return -1;
	}
}
int edge_sort_bf2ldeg(struct edge_hash *a, struct edge_hash *b)
{
	if(0 != maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6))
		return maccmp(a->edge_key.lh_mac, b->edge_key.lh_mac, 6);
	if(a->bytes_f2l < b->bytes_f2l){
		return 1;
	}
	else if(a->bytes_f2l == b->bytes_f2l){
		return 0;
	}
	else{
		return -1;
	}
}

int rf_sort_endtime(struct r_flow *a, struct r_flow *b)
{
	if(a->end.tv_sec < b->end.tv_sec){
		return 1;
	} else if (a->end.tv_sec == b->end.tv_sec){
		return 0;
	} else {
		return -1;
	}
}

int dns_sort_ttl(struct dns_record *a, struct dns_record *b)
{
	if(a->ttl < b->ttl){
		return 1;
	} else if (a->ttl == b->ttl){
		return 0;
	} else {
		return -1;
	}
}

void handle_exp_stat(struct ipflow_exp_stat *exp_stat,
					uint64_t *expired, 
					uint64_t *active)
{
	//printf("S %s\n", __FUNCTION__);
	*expired = exp_stat->expired_count;
	*active = exp_stat->active_count;
#ifdef NFLC_DEBUG
	printf("#Expired flows: %llu\n#Active flows: %llu\n", 
				*expired, *active);
#endif
}

void handle_exp_entry(__be32 lan_addr, __be32 lan_mask,
					struct ipflow_exp *exp_entry, 
					int is_active)
{
	//printf("S %s\n", __FUNCTION__);
	struct timeval now;
	struct c_flow *tmp_cf;
	struct r_flow *tmp_rf;

	/* Get current time */
	gettimeofday(&now, NULL);

	if(is_active!=0){
		/* Update the table for the latest export: cf w/ ports */
		HASH_FIND(hh, cf_hhead, &exp_entry->seq, sizeof(uint64_t), tmp_cf);
		/* Not found in hash table */
		if(tmp_cf == NULL){
			tmp_cf = malloc(sizeof(struct c_flow));
			INIT_CFLOW(tmp_cf, exp_entry);
			HASH_ADD(hh, cf_hhead, seq, sizeof(uint64_t), tmp_cf);
		}
	}

	/* Update the table for the latest export: rf */
	HASH_FIND(hh, rf_hhead, &exp_entry->seq, sizeof(uint64_t), tmp_rf);
	/* Not found in hash table */
	if(tmp_rf == NULL){
		tmp_rf = malloc(sizeof(struct r_flow));
		INIT_RFLOW(tmp_rf, exp_entry, is_active);
		HASH_ADD(hh, rf_hhead, seq, sizeof(uint64_t), tmp_rf);
	}
	else{
		UPDATE_RFLOW(tmp_rf, exp_entry, is_active);
	}
} 

void handle_dns_entry(struct dns_record_exp *entry)
{
	//printf("S %s\n", __FUNCTION__);
	struct dns_record *dnsrec;

	HASH_FIND(hh, dns_hhead, &entry->ip, sizeof(__be32), dnsrec);
	if(dnsrec == NULL){
		dnsrec = malloc(sizeof(struct dns_record));
		dnsrec->ip = entry->ip;
		dnsrec->ttl = DNS_TTL;
		dnsrec->id = HASH_COUNT(dns_hhead)+1;
		strncpy(dnsrec->name, entry->name, DNS_NAME_LEN);
		HASH_ADD(hh, dns_hhead, ip, sizeof(__be32), dnsrec);
	}else{
		dnsrec->ttl = DNS_TTL;
		strncpy(dnsrec->name, entry->name, DNS_NAME_LEN);
	}
}

void gen_edges()
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	//printf("S %s\n", __FUNCTION__);
	struct c_flow *cf, *tmp_cf;
	/* Hash table entry of EDGE */
	struct edge_hash *tmp_edge=NULL, *pre_edge=NULL;
	struct edge_hash_key tmp_edge_key, pre_edge_key;
	struct arp_tbl *tmp_arp;
	struct lh_stat *tmp_lh;
	int i=0, j=0, k=0, l=0, ip1=0, ip0=0, ip0p=0;
	int bits=0, aidx=0, bidx=0;

	/* Sort CF Table according to Src&Dst address pair */
	HASH_SORT(cf_hhead, cf_sort_addr);

	uint16_t top_port_idx[3];
	uint16_t port_lvl2[PORT_LVL2];
	uint16_t port_lvl1[PORT_LVL1];
	uint16_t port_lvl0[PORT_LVL0];

	// clean port data
	memset(top_port_idx, 0, sizeof(uint16_t)*3);	
	memset(port_lvl2, 0, sizeof(uint16_t)*PORT_LVL2);
	memset(port_lvl1, 0, sizeof(uint16_t)*PORT_LVL1);
	memset(port_lvl0, 0, sizeof(uint16_t)*PORT_LVL0);

	/* Assign edge key */
	memset(&tmp_edge_key, 0, sizeof(struct edge_hash_key));
	/* Traverse CF and update Edges Table */
	HASH_ITER(hh, cf_hhead, cf, tmp_cf){
		if((addr_is_local(cf->flow_key.saddr) 
				&& !addr_is_local(cf->flow_key.daddr) 
				&& !addr_is_special(cf->flow_key.daddr)) 
			|| (addr_is_local(cf->flow_key.daddr)
				&& !addr_is_local(cf->flow_key.saddr) 
				&& !addr_is_special(cf->flow_key.saddr))) {

			estat.flows_total += 1;
			
			if(addr_is_local(cf->flow_key.saddr)){
				/* Search ARP table */
				HASH_FIND(hh, arp_hhead, &(cf->flow_key.saddr), 
					sizeof(__be32), tmp_arp);
				if(tmp_arp == NULL){
					fprintf(stderr, 
						"Local IP address not found in ARP table\n");
				}
				else{
					COPY_MAC(tmp_edge_key.lh_mac, tmp_arp->lh_mac);
					tmp_edge_key.faddr = cf->flow_key.daddr;
				}
			}
			else{
				/* Search ARP table */
				HASH_FIND(hh, arp_hhead, &(cf->flow_key.daddr), 
					sizeof(__be32), tmp_arp);
				if(tmp_arp == NULL){
					fprintf(stderr, 
						"Local IP address not found in ARP table\n");
				}
				else{
					COPY_MAC(tmp_edge_key.lh_mac, tmp_arp->lh_mac);
					tmp_edge_key.faddr = cf->flow_key.saddr;
				}
			}

			/* Update edges hash table*/
			HASH_FIND(hh, edges_hhead, &tmp_edge_key, 
					sizeof(struct edge_hash_key), tmp_edge);
			/* Edge not found in hash table */
			if(tmp_edge == NULL){
				if(pre_edge != NULL && pre_edge->prot_bitmap!=4){
					/* get top 3 ports */
					GET_TOP_PORTS(top_port_idx);
					/* add port data to previous edge */
					ADD_EDGE_PORT_DATA(pre_edge, top_port_idx, port_lvl0);
				}
				/* clean port data */
				memset(top_port_idx, 0, sizeof(uint16_t)*3);
				memset(port_lvl2, 0, sizeof(uint16_t)*PORT_LVL2);
				memset(port_lvl1, 0, sizeof(uint16_t)*PORT_LVL1);
				memset(port_lvl0, 0, sizeof(uint16_t)*PORT_LVL0);

				/* create new edge entry*/
				tmp_edge = malloc(sizeof(struct edge_hash));
				memset(tmp_edge, 0, sizeof(struct edge_hash));
				if(addr_is_local(cf->flow_key.saddr)){
					/* update port hash */
					if(cf->flow_key.protocol != IPPROTO_ICMP)
						UPDATE_PORT_HASH(ntohs(cf->flow_key.dport));
					INIT_EDGE_HASH_L2F(tmp_edge, tmp_edge_key,
							cf->export_count,
							cf->pkts, cf->bytes, 
							cf->intvl_pkts, 
							cf->intvl_bytes,
							cf->flow_key.protocol);
					UPDATE_EDGE_STAT_L2F(cf->pkts,
							cf->bytes,
							cf->intvl_pkts,
							cf->intvl_bytes);
				}
				else{
					if(cf->flow_key.protocol != IPPROTO_ICMP)
						UPDATE_PORT_HASH(ntohs(cf->flow_key.sport));
					INIT_EDGE_HASH_F2L(tmp_edge, tmp_edge_key,
							cf->export_count,
							cf->pkts, cf->bytes,
							cf->intvl_pkts, 
							cf->intvl_bytes,
							cf->flow_key.protocol);
					UPDATE_EDGE_STAT_F2L(cf->pkts,
							cf->bytes,
							cf->intvl_pkts,
							cf->intvl_bytes);
				}
				HASH_ADD(hh, edges_hhead, edge_key, 
						sizeof(struct edge_hash_key), tmp_edge);
			}
			/* Edge found in hash table */
			else{
				if(addr_is_local(cf->flow_key.saddr)){
					if(cf->flow_key.protocol != IPPROTO_ICMP)
						UPDATE_PORT_HASH(ntohs(cf->flow_key.dport));
					UPDATE_EDGE_HASH_L2F(tmp_edge,
							cf->export_count,
							cf->pkts, cf->bytes,
							cf->intvl_pkts, 
							cf->intvl_bytes,
							cf->flow_key.protocol);
					UPDATE_EDGE_STAT_L2F(cf->pkts,
							cf->bytes,
							cf->intvl_pkts,
							cf->intvl_bytes);
				}
				else{
					if(cf->flow_key.protocol != IPPROTO_ICMP)
						UPDATE_PORT_HASH(ntohs(cf->flow_key.sport));
					UPDATE_EDGE_HASH_F2L(tmp_edge,
							cf->export_count,
							cf->pkts, cf->bytes, 
							cf->intvl_pkts, 
							cf->intvl_bytes,
							cf->flow_key.protocol);
					UPDATE_EDGE_STAT_F2L(cf->pkts,
							cf->bytes,
							cf->intvl_pkts,
							cf->intvl_bytes);
				}
			}
			pre_edge = tmp_edge;

			/* Update local host hash table */
			HASH_FIND(hh, lh_hhead, &tmp_edge_key.lh_mac, 6, tmp_lh);
			if(tmp_lh == NULL){
				tmp_lh = malloc(sizeof(struct lh_stat));
				COPY_MAC(tmp_lh->lh_mac, tmp_edge_key.lh_mac);
				if(addr_is_local(cf->flow_key.saddr)){
					tmp_lh->c_ip = cf->flow_key.saddr;
					INIT_LH_HASH_L2F(tmp_lh, 
							cf->pkts, cf->bytes,
							(cf->intvl_pkts > 0 ? 1 : 0),
							cf->intvl_pkts, 
							cf->intvl_bytes);
					tmp_lh->lid = gen_lid(cf->flow_key.saddr);
				}
				else{
					tmp_lh->c_ip = cf->flow_key.daddr;
					INIT_LH_HASH_F2L(tmp_lh,
							cf->pkts, cf->bytes,
							(cf->intvl_pkts > 0 ? 1 : 0),
							cf->intvl_pkts, 
							cf->intvl_bytes);
					tmp_lh->lid = gen_lid(cf->flow_key.daddr);
				}
				if(tmp_lh->lid == WAN_ADDR_ID){
					snprintf(tmp_lh->host_name, HOST_NAME_LEN, 
								"Wildcat router");
					tmp_lh->host_name[HOST_NAME_LEN]='\0';
				}
				HASH_ADD(hh, lh_hhead, lh_mac, 6, tmp_lh);
			}
			else{
				if(addr_is_local(cf->flow_key.saddr)){
					tmp_lh->c_ip = cf->flow_key.saddr;
					UPDATE_LH_HASH_L2F(tmp_lh, 
							cf->pkts, cf->bytes,
							(cf->intvl_pkts > 0 ? 1 : 0),
							cf->intvl_pkts, 
							cf->intvl_bytes);
				}
				else{
					tmp_lh->c_ip = cf->flow_key.daddr;
					UPDATE_LH_HASH_F2L(tmp_lh, 
							cf->pkts, cf->bytes,
							(cf->intvl_pkts > 0 ? 1 : 0),
							cf->intvl_pkts, 
							cf->intvl_bytes);
				}
			}		
		} // End of if() for updating edge hash table
	}// End of CF traversal
	if(pre_edge != NULL && pre_edge->prot_bitmap!=4){
		/* get top 3 ports */
		GET_TOP_PORTS(top_port_idx);
		/* Add port data to the last edge entry*/
		ADD_EDGE_PORT_DATA(pre_edge, top_port_idx, port_lvl0);
	}
}
/******
 * Fuctions for initiating hashtable
 ******/
void import_lhstat_entry(struct lh_stat_exp *tmp_lh_exp)
{
	struct lh_stat *tmp_lh;
	tmp_lh = malloc(sizeof(struct lh_stat));
	COPY_LHSTAT_FIELDS(tmp_lh, tmp_lh_exp);
	HASH_ADD(hh, lh_hhead, lh_mac, 6, tmp_lh);
}
int init_lhstat(char *drohn_dir)
{
	//printf("S %s\n", __FUNCTION__);
	struct lh_stat *del_lh, *tmp_del_lh;
	struct lh_stat_exp *tmp_lh_exp;
	struct magic_head *mh;
	char mh_buf[MH_SIZE];
	char lh_buf[LH_STAT_EXP_SIZE];
	int idx;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];
	int has_new_lids = 0;

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_LHSTAT_FILE, drohn_dir);
	nxt_lid = 0;
	if ((fp = fopen(file_path,"r")) != NULL){
		if(!feof(fp)){
			fread(mh_buf, MH_SIZE, 1, fp);
			mh = (struct magic_head *)mh_buf;
		}
		if(strncmp(mh->magic_word, "nfl", 3) == 0){
			idx = 0;
			while(!feof(fp)){
				if(fread(lh_buf, LH_STAT_EXP_SIZE, 1, fp)>0
						&& idx<mh->entry_count){
					tmp_lh_exp = (struct lh_stat_exp *)lh_buf;
					import_lhstat_entry(tmp_lh_exp);
					if(tmp_lh_exp->lid != WAN_ADDR_ID 
							&& tmp_lh_exp->lid >= nxt_lid){
						nxt_lid = tmp_lh_exp->lid+1;
					}
					idx++;
				}
			}
			if(idx!=mh->entry_count){
				/* File damaged! Destroy hashtable*/
				HASH_ITER(hh, lh_hhead, del_lh, tmp_del_lh){
					HASH_DEL(lh_hhead, del_lh);
					free(del_lh);
				}
				HASH_CLEAR(hh, lh_hhead);
				nxt_lid = 0;
				has_new_lids = 1;
			}
		}
		fclose(fp);
	} else {
		has_new_lids = 1;
	}
	return has_new_lids;
}

void import_dns_entry(struct dns_tbl_exp *tmp_dns_exp, int idx)
{
	struct dns_record *tmp_dns;
	tmp_dns = malloc(sizeof(struct dns_record));
	COPY_DNS_FIELDS(tmp_dns, tmp_dns_exp);
	tmp_dns->id = idx;
	tmp_dns->ttl--;
	HASH_ADD(hh, dns_hhead, ip, sizeof(__be32), tmp_dns);
}

void init_dns(char *drohn_dir)
{
	//printf("S %s\n", __FUNCTION__);
	struct dns_record *del_dns, *tmp_del_dns;
	struct dns_tbl_exp *tmp_dns_exp;
	struct magic_head *mh;
	char mh_buf[MH_SIZE];
	char dns_buf[DNS_EXP_SIZE];
	int idx;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_DNS_FILE, drohn_dir);
	if ((fp = fopen(file_path,"r")) != NULL){
		if(!feof(fp)){
			fread(mh_buf, MH_SIZE, 1, fp);
			mh = (struct magic_head *)mh_buf;
		}
		if(strncmp(mh->magic_word, "nfl", 3) == 0){
			idx = 0;
			while(!feof(fp)){
				if(fread(dns_buf, DNS_EXP_SIZE, 1, fp)>0
						&& idx<mh->entry_count){
					tmp_dns_exp = (struct dns_tbl_exp *)dns_buf;
					import_dns_entry(tmp_dns_exp, idx++);
				}
			}
			if(idx!=mh->entry_count){
				/* File damaged! Destroy hashtable*/
				HASH_ITER(hh, dns_hhead, del_dns, tmp_del_dns){
					HASH_DEL(dns_hhead, del_dns);
					free(del_dns);
				}
				HASH_CLEAR(hh, dns_hhead);
			}
		}
		fclose(fp);
	}
}

void import_arp_entry(struct arp_tbl_exp *tmp_arp_exp)
{
	struct arp_tbl *tmp_arp;
	tmp_arp = malloc(sizeof(struct arp_tbl));
	COPY_ARP_FIELDS(tmp_arp, tmp_arp_exp);
	HASH_ADD(hh, arp_hhead, addr, sizeof(__be32), tmp_arp);
}
void init_arp(char *drohn_dir)
{
	//printf("S %s\n", __FUNCTION__);
	struct arp_tbl *del_arp, *tmp_del_arp;
	struct arp_tbl_exp *tmp_arp_exp;
	struct magic_head *mh;
	char mh_buf[MH_SIZE];
	char arp_buf[ARP_EXP_SIZE];
	int idx;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_ARP_FILE, drohn_dir);
	if ((fp = fopen(file_path,"r")) != NULL){
		if(!feof(fp)){
			fread(mh_buf, MH_SIZE, 1, fp);
			mh = (struct magic_head *)mh_buf;
		}
		if(strncmp(mh->magic_word, "nfl", 3) == 0){
			idx = 0;
			while(!feof(fp)){
				if(fread(arp_buf, ARP_EXP_SIZE, 1, fp)>0
						&& idx<mh->entry_count){
					tmp_arp_exp = (struct arp_tbl_exp *)arp_buf;
					import_arp_entry(tmp_arp_exp);
					idx++;
				}
			}
			if(idx!=mh->entry_count){
				/* File damaged! Destroy hashtable*/
				HASH_ITER(hh, arp_hhead, del_arp, tmp_del_arp){
					HASH_DEL(arp_hhead, del_arp);
					free(del_arp);
				}
				HASH_CLEAR(hh, arp_hhead);
			}
		}
		fclose(fp);
	}
}

void import_rf_entry(struct r_flow_exp *tmp_rf_exp)
{
	struct r_flow *tmp_rf;
	tmp_rf = malloc(sizeof(struct r_flow));
	COPY_RF_FIELDS(tmp_rf, tmp_rf_exp);
	HASH_ADD(hh, rf_hhead, seq, sizeof(uint64_t), tmp_rf);
}
void init_rf(char *drohn_dir)
{
	//printf("S %s\n", __FUNCTION__);
	struct r_flow *del_rf, *tmp_del_rf;
	struct r_flow_exp *tmp_rf_exp;
	struct magic_head *mh;
	char mh_buf[MH_SIZE];
	char rf_buf[RF_EXP_SIZE];
	int idx;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_RF_FILE, drohn_dir);
	if ((fp = fopen(file_path,"r")) != NULL){
		if(!feof(fp)){
			fread(mh_buf, MH_SIZE, 1, fp);
			mh = (struct magic_head *)mh_buf;
		}
		if(strncmp(mh->magic_word, "nfl", 3) == 0){
			idx = 0;
			while(!feof(fp)){
				if(fread(rf_buf, RF_EXP_SIZE, 1, fp)>0
						&& idx<mh->entry_count){
					tmp_rf_exp = (struct r_flow_exp *)rf_buf;
					import_rf_entry(tmp_rf_exp);
					idx++;
				}
			}
			if(idx!=mh->entry_count){
				/* File damaged! Destroy hashtable*/
				HASH_ITER(hh, rf_hhead, del_rf, tmp_del_rf){
					HASH_DEL(rf_hhead, del_rf);
					free(del_rf);
				}
				HASH_CLEAR(hh, rf_hhead);
			}
		}
		fclose(fp);
	}
}

/******
 * Functions for hashtable backup
 ******/
void backup_dns(char *drohn_dir)
{
	struct dns_record *dns, *tmp_dns;
	struct dns_tbl_exp *dns_exp;
	struct magic_head mh;
	uint32_t mh_count = 0, idx = 0;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_DNS_FILE, drohn_dir);
	dns_exp = malloc(sizeof(struct dns_tbl_exp));
	fp = fopen(file_path, "wb");

	HASH_SORT(dns_hhead, dns_sort_ttl);

	HASH_ITER(hh, dns_hhead, dns, tmp_dns){
		if(dns->ttl>0){
			mh_count += 1;
		} else {
			break;
		}
	}

	/* Write magic head to file first */
	if(mh_count > DNS_TBL_LIMIT){
		BUILD_MAGIC_HEAD(mh, DNS_TBL_THR);
	} else {
		BUILD_MAGIC_HEAD(mh, mh_count);
	}
	fwrite(&mh, sizeof(struct magic_head), 1, fp);

	if(mh_count > DNS_TBL_LIMIT){
		HASH_ITER(hh, dns_hhead, dns, tmp_dns){
			if(dns->ttl>0 && idx < DNS_TBL_THR){
				/* Prepare LHSTAT entry */
				COPY_DNS_FIELDS(dns_exp, dns);
				/* Write to file */
				fwrite(dns_exp, DNS_EXP_SIZE, 1, fp);
				idx++;
			} else {
				break;
			}
		}
	} else {
		HASH_ITER(hh, dns_hhead, dns, tmp_dns){
			if(dns->ttl>0){
				/* Prepare LHSTAT entry */
				COPY_DNS_FIELDS(dns_exp, dns);
				/* Write to file */
				fwrite(dns_exp, DNS_EXP_SIZE, 1, fp);
			} else {
				break;
			}
		}
	}
	free(dns_exp);
	fclose(fp);
}

void backup_arp(char *drohn_dir)
{
	struct arp_tbl *arp, *tmp_arp;
	struct arp_tbl_exp *arp_exp;
	struct magic_head mh;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_ARP_FILE, drohn_dir);
	arp_exp = malloc(sizeof(struct arp_tbl_exp));
	fp = fopen(file_path, "wb");

	/* Write magic head to file first */
	BUILD_MAGIC_HEAD(mh, HASH_COUNT(arp_hhead));
	fwrite(&mh, sizeof(struct magic_head), 1, fp);

	HASH_ITER(hh, arp_hhead, arp, tmp_arp){
		/* Prepare LHSTAT entry */
		COPY_ARP_FIELDS(arp_exp, arp);
		/* Write to file */
		fwrite(arp_exp, ARP_EXP_SIZE, 1, fp);
	}
	free(arp_exp);
	fclose(fp);
}

void backup_lhstat(char *drohn_dir)
{
	struct lh_stat *lh, *tmp_lh;
	struct lh_stat_exp *lh_exp;
	struct magic_head mh;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_LHSTAT_FILE, drohn_dir);
	lh_exp = malloc(sizeof(struct lh_stat_exp));
	fp = fopen(file_path, "wb");

	/* Write magic head to file first */
	BUILD_MAGIC_HEAD(mh, HASH_COUNT(lh_hhead));
	fwrite(&mh, sizeof(struct magic_head), 1, fp);

	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		/* Prepare LHSTAT entry */
		COPY_LHSTAT_FIELDS(lh_exp, lh);
		/* Write to file */
		fwrite(lh_exp, LH_STAT_EXP_SIZE, 1, fp);
	}
	free(lh_exp);
	fclose(fp);
}

void backup_rf(char *drohn_dir)
{
	struct r_flow *rf, *tmp_rf;
	struct r_flow_exp *rf_exp;
	struct timeval now;
	struct magic_head mh;
	uint32_t mh_count = 0, idx = 0;
	FILE *fp;
	char file_path[MAX_FILE_NAME_LEN];

	snprintf(file_path, sizeof(file_path),
				"%s/backup/"NFLC_RF_FILE, drohn_dir);
	rf_exp = malloc(sizeof(struct r_flow_exp));
	fp = fopen(file_path, "wb");

	HASH_SORT(rf_hhead, rf_sort_endtime);

	gettimeofday(&now, NULL);

	HASH_ITER(hh, rf_hhead, rf, tmp_rf){
		if(rf->end.tv_sec >= (now.tv_sec-RE_DUR)){
			mh_count += 1;
		} else {
			break;
		}
	}
	/* Write magic head to file first */
	if(mh_count > RF_TBL_LIMIT){
		BUILD_MAGIC_HEAD(mh, RF_TBL_THR);
	} else {
		BUILD_MAGIC_HEAD(mh, mh_count);
	}
	fwrite(&mh, sizeof(struct magic_head), 1, fp);

	if(mh_count > RF_TBL_LIMIT){
		HASH_ITER(hh, rf_hhead, rf, tmp_rf){
			if(rf->end.tv_sec >= (now.tv_sec-RE_DUR) 
					&& idx < RF_TBL_THR){
				/* Prepare rf entry */
				COPY_RF_FIELDS(rf_exp, rf);
				/* Write to file */
				fwrite(rf_exp, RF_EXP_SIZE, 1, fp);
				idx++;
			} else {
				break;
			}
		}
	} else {
		HASH_ITER(hh, rf_hhead, rf, tmp_rf){
			if(rf->end.tv_sec >= (now.tv_sec-RE_DUR)){
				/* Prepare rf entry */
				COPY_RF_FIELDS(rf_exp, rf);
				/* Write to file */
				fwrite(rf_exp, RF_EXP_SIZE, 1, fp);
			} else {
				break;
			}
		}
	}
	free(rf_exp);
	fclose(fp);
}

void clean_edges_hash()
{
	struct edge_hash *del_edge, *tmp_del_edge;
	HASH_ITER(hh, edges_hhead, del_edge, tmp_del_edge){
		HASH_DEL(edges_hhead, del_edge);
		free(del_edge);
	}
	HASH_CLEAR(hh, edges_hhead);
}

void clean_cf()
{
	//printf("S %s\n", __FUNCTION__);
	struct c_flow *del_cf, *tmp_del_cf;
	HASH_ITER(hh, cf_hhead, del_cf, tmp_del_cf){
		HASH_DEL(cf_hhead, del_cf);
		free(del_cf);
	}
	HASH_CLEAR(hh, cf_hhead);
}

void clean_rf()
{
	//printf("S %s\n", __FUNCTION__);
	struct r_flow *del_rf, *tmp_del_rf;
	HASH_ITER(hh, rf_hhead, del_rf, tmp_del_rf){
		HASH_DEL(rf_hhead, del_rf);
		free(del_rf);
	}
	HASH_CLEAR(hh, rf_hhead);
}

void clean_lhstat()
{
	struct lh_stat *del_lh, *tmp_del_lh;
	HASH_ITER(hh, lh_hhead, del_lh, tmp_del_lh){
		HASH_DEL(lh_hhead, del_lh);
		free(del_lh);
	}
	HASH_CLEAR(hh, lh_hhead);
	nxt_lid = 0;
}

void clean_arp()
{
	struct arp_tbl *del_arp, *tmp_del_arp;
	HASH_ITER(hh, arp_hhead, del_arp, tmp_del_arp){
		HASH_DEL(arp_hhead, del_arp);
		free(del_arp);
	}
	HASH_CLEAR(hh, arp_hhead);
}

void clean_dns()
{
	struct dns_record *del_dns, *tmp_del_dns;
	HASH_ITER(hh, dns_hhead, del_dns, tmp_del_dns){
		HASH_DEL(dns_hhead, del_dns);
		free(del_dns);
	}
	HASH_CLEAR(hh, dns_hhead);
}

void refresh_table_lhstat()
{
	struct lh_stat *lh, *tmp_lh;
	/* Zero out fields of lh_stat c-entries */
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		ZERO_LH_HASH_CURRENT_FIELDS(lh);
	}
}

void update_table_lhstat()
{
	struct lh_stat *lh, *tmp_lh;

	HASH_SORT(lh_hhead, lhstat_sort_lid);

	/* Update EWMA fields of lh_stat entries */
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		UPDATE_LH_HASH_EWMA(lh);
	}
}

void output_table_lhstat()
{
	struct lh_stat *lh, *tmp_lh;
	/* Output lhstat entries */
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		printf("LID: %u  MAC: %02x:%02x:%02x:%02x:%02x:%02x  Name: %s\n"
				"  Host: %lu  Flows out: %lu  Flows in: %lu"
				"  Packets out: %lu  Packets in: %lu"
				"  Bytes out: %llu  Bytes in: %llu\n",
				lh->lid, 
				lh->lh_mac[0], lh->lh_mac[1], lh->lh_mac[2], 
				lh->lh_mac[3], lh->lh_mac[4], lh->lh_mac[5],
				lh->host_name, lh->c_hosts,
				lh->c_flows_l2f, lh->c_flows_f2l,
				lh->c_pkts_l2f, lh->c_pkts_f2l,
				lh->c_bytes_l2f, lh->c_bytes_f2l);
	}
}

int read_hit_count(char *drohn_dir)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	char hit_count_fpath[MAX_FILE_NAME_LEN];
	char hit_count_tmp_fpath[MAX_FILE_NAME_LEN];
	FILE *fp, *fp_tmp;
	int ret = -1;

	snprintf(hit_count_fpath, sizeof(hit_count_fpath), 
				"%s/backup/"HITCOUNT_FILE, drohn_dir);
	if((fp = fopen(hit_count_fpath, "r")) == NULL){
		fprintf(stderr, "Cannot find hit count file.\n");
	} else {
		fscanf(fp, "%d", &ret);
		fclose(fp);
	}

	snprintf(hit_count_tmp_fpath, sizeof(hit_count_tmp_fpath), 
				"%s/backup/"HITCOUNT_TMP_FILE, drohn_dir);
	if((fp_tmp = fopen(hit_count_tmp_fpath, "w")) == NULL){
		fprintf(stderr, "Error in writing hit count file.\n");
	} else {
		fprintf(fp_tmp, "%d\n", 0);
		fclose(fp_tmp);
		if(ret<0){
			ret = 0;
		}
		if(rename(hit_count_tmp_fpath, hit_count_fpath) != 0) {
			/* Handle error condition */
			fprintf(stderr, "Error in moving hit count file.\n");
		}
	}

	return ret;
}
/*
 * export_edges() also updates number of connected foreign hosts
 * for each local host during the current flow export
 */
void export_edges(char *drohn_dir, int has_new_lids)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	struct edge_hash *edge, *tmp_edge;
	struct lh_stat *tmp_lh;
	char drohn_id[DROHN_ID_LEN+1];
	char exp_fpath_tmp[MAX_FILE_NAME_LEN];
	char exp_fpath[MAX_FILE_NAME_LEN];
	struct timeval now;
	uint16_t tmp_lid;
	int hit_count = 0;
	//uint32_t tmp_fid;
	unsigned char tmp_fid[FID_LEN];
	FILE *id_fp, *fp;

	/* Get DR.OHN ID */
	if((id_fp = fopen(DROHN_ID_FILE, "r")) == NULL){
		die_with_error("Error in opening DROHN_ID_FILE.");
	}
	if (fread(drohn_id, 1, DROHN_ID_LEN, id_fp) != DROHN_ID_LEN){
		die_with_error("Error in reading DROHN_ID_FILE.");
	}
	drohn_id[DROHN_ID_LEN] = '\0';

	/* Get current time */
	gettimeofday(&now, NULL);

	snprintf(exp_fpath, sizeof(exp_fpath), 
				"%s/"UPLOAD_DIR_NAME"/"EDGE_OUTPUT_PREFIX"%s_%ld",
				drohn_dir, drohn_id, now.tv_sec);
	snprintf(exp_fpath_tmp, sizeof(exp_fpath_tmp), 
				"%s/"UPLOAD_TMP_DIR_NAME"/"EDGE_OUTPUT_PREFIX"%s_%ld",
				drohn_dir, drohn_id, now.tv_sec);

	if((fp = fopen(exp_fpath_tmp, "w")) == NULL){
		die_with_error("Error in opening edge export file.");
	}

	estat.edges_total = HASH_COUNT(edges_hhead);

	/* Read hit count of dashboard */
	hit_count = read_hit_count(drohn_dir);

	/*********** 
	 * Edge Stat Output Format: 
	 * #edges,#flows,#flows->,#flows<-,#pkts->,#pkts<-,#bytes->,#bytes<-,
	 * #i_flows,#i_flows->,#i_flows<-,#i_pkts->,#i_pkts<-,
	 * #i_bytes->,#i_bytes<-,hit_count
	 ***********/
	fprintf(fp, "%lu,%lu,%lu,%lu,%lu,%lu,%llu,%llu,"
				"%lu,%lu,%lu,%lu,%lu,%llu,%llu,%d,%d\n",
			estat.edges_total, estat.flows_total,
			estat.flows_l2f, estat.flows_f2l,
			estat.pkts_l2f, estat.pkts_f2l,
			estat.bytes_l2f, estat.bytes_f2l, 
			estat.intvl_flows_total,
			estat.intvl_flows_l2f, estat.intvl_flows_f2l,
			estat.intvl_pkts_l2f, estat.intvl_pkts_f2l,
			estat.intvl_bytes_l2f, estat.intvl_bytes_f2l,
			hit_count, has_new_lids);

	/* Sort edges by MAC address */
	HASH_SORT(edges_hhead, edge_sort_addr);
	
	/* Initialize crpyto library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	tmp_lid = 0;
	HASH_ITER(hh, edges_hhead, edge, tmp_edge){
		/* Get local host ID */
		HASH_FIND(hh, lh_hhead, &(edge->edge_key.lh_mac), 6, tmp_lh);
		if(tmp_lh == NULL){
			fprintf(stderr, "1.LH_STAT hash table error!\n");
		}
		else{
			/* Update host count for current interval */
			tmp_lh->c_hosts += 1;
			if(edge->intvl_flows_l2f+edge->intvl_flows_f2l > 0){
				tmp_lh->ci_hosts += 1;
			}
			tmp_lid = tmp_lh->lid;
		}
		/* Generate foreign host ID */
		encrypt((uint32_t)edge->edge_key.faddr, 16, fid_key, tmp_fid);

		/*********** 
		 * Edge Export Output Format: 
		 * LID,FID,#flows->,#flows<-,#pkts->,#pkts<-,#bytes->,#bytes<-,
		 *    #intvl_flows->,#intvl_flows<-,#intvl_pkts->,#intvl_pkts<-,
		 *    #intvl_bytes->,#intvl_bytes<-,protocols,port&cnt[3]
		 ***********/
		if(if_conf.use_oui == 1 && tmp_lh != NULL){
			char mac_oui[8];
			snprintf(mac_oui, sizeof(mac_oui),
					"%02x%02x%02x",
					tmp_lh->lh_mac[0],tmp_lh->lh_mac[1],tmp_lh->lh_mac[2]);
			fprintf(fp, "%u-%s,", tmp_lid, mac_oui);
		}else{
			fprintf(fp, "%u,", tmp_lid);
		}
		fprintf(fp, "%s,%lu,%lu,%lu,%lu,%llu,%llu,"
					"%lu,%lu,%lu,%lu,%llu,%llu,%u,"
					"%u,%u,%u,%u,%u,%u,%lu\n",
				tmp_fid,
				edge->flows_l2f, edge->flows_f2l,
				edge->pkts_l2f, edge->pkts_f2l,
				edge->bytes_l2f, edge->bytes_f2l,
				edge->intvl_flows_l2f, edge->intvl_flows_f2l,
				edge->intvl_pkts_l2f, edge->intvl_pkts_f2l,
				edge->intvl_bytes_l2f, edge->intvl_bytes_f2l,
				edge->prot_bitmap, 
				edge->ports[0].port, edge->ports[0].cnt,
				edge->ports[1].port, edge->ports[1].cnt,
				edge->ports[2].port, edge->ports[2].cnt,
				edge->max_dur);
	}
	/* Clean up crypto */
	EVP_cleanup();
	ERR_free_strings();

	fclose(fp);

	/* Move export file to upload dir */
	if (rename(exp_fpath_tmp, exp_fpath) != 0) {
		/* Handle error condition */
		fprintf(stderr, "Error in moving export file.\n");
	}
}

int encrypt(uint32_t faddr, int padded_faddr_len, 
			unsigned char *key, unsigned char *fid_b64)
{
	unsigned char ciphertext[FID_KEY_LEN];
	unsigned char *cipher_b64;
	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len;
	uint32_t padded_faddr[4];
	padded_faddr[0]=faddr;
	padded_faddr[1]=4096; 
	padded_faddr[2]=2048;
	padded_faddr[3]=1024;

	/* Create context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handle_crypto_error();

	/* Initialize */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handle_crypto_error();
	/* Do not do padding */
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* Encrypt */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, 
						(unsigned char *)padded_faddr, padded_faddr_len))
		handle_crypto_error();
	ciphertext_len = len;

	/* Finalize */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handle_crypto_error();
	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	cipher_b64 = encfid_b64(ciphertext);
	strncpy(fid_b64, cipher_b64, FID_LEN);
	free(cipher_b64);

	return ciphertext_len;
}

/******
 Retired fids related functions:
 add_rfid()  add to tail
 rm_rfid()  remove from head and return fid value
 ******/
void add_bglink(int src, int tgt, uint64_t val){
	struct bglink_list *tmp_bglink;
	tmp_bglink = malloc(sizeof(struct bglink_list));
	tmp_bglink->v_src = src;
	tmp_bglink->v_tgt = tgt;
	tmp_bglink->v_val = val;
	tmp_bglink->next=NULL;
	if(bglink_tail != NULL)
		bglink_tail->next = tmp_bglink;
	bglink_tail = tmp_bglink;
	if(bglink_head == NULL)
		bglink_head = tmp_bglink;
	bglink_count += 1;
}

struct bglink_list rm_bglink(){
	struct bglink_list *tmp_bglink = bglink_head;
	struct bglink_list ret;
	ret.v_src = -1;
	ret.v_tgt = -1;
	ret.v_val = -1;
	ret.next = NULL;
	if(bglink_head == NULL)
		return ret;
	bglink_head = bglink_head->next;
	ret.v_src = tmp_bglink->v_src;
	ret.v_tgt = tmp_bglink->v_tgt;
	ret.v_val = tmp_bglink->v_val;
	free(tmp_bglink);
	bglink_count -= 1;
	return ret;
}

void clean_jf_hash()
{
	struct json_fid_hash *del_jf, *tmp_del_jf;
	HASH_ITER(hh, jf_hhead, del_jf, tmp_del_jf){
		HASH_DEL(jf_hhead, del_jf);
		free(del_jf);
	}
	HASH_CLEAR(hh, jf_hhead);
}

void create_jf_entry(__be32 faddr, int idx)
{
	struct json_fid_hash *jf_entry;
	jf_entry = malloc(sizeof(struct json_fid_hash));
	jf_entry->faddr = faddr;
	jf_entry->node_idx = idx;
	HASH_ADD(hh, jf_hhead, faddr, sizeof(__be32), jf_entry);
}
/*
 * tabHeader_1: Connected Hosts(1.Cur, 2.Avg) 
 * tabHeader_2: Two-way Flows(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_3: Two-way Packets(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_4: Two-way Bytes(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_5: Outgoing Flows(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_6: Outgoing Packets(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_7: Outgoing Bytes(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_8: Incoming Flows(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_9: Incoming Packets(1.Cur, 2.Avg, 3.Top_K)
 * tabHeader_10: Incoming Bytes(1.Cur, 2.Avg, 3.Top_K)
 */
void gen_top_k_json(char *drohn_dir, int max_edges_num)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	//printf("S %s\n", __FUNCTION__);
	struct edge_hash *edge, *tmp_edge;
	struct lh_stat *tmp_lh;
	struct dns_record *tmp_dns;
	struct json_fid_hash *tmp_jf;
	struct bglink_list tmp_bgl;
	unsigned char tmp_mac[6];
	char mac_addr[18];
	char ip_addr[16];
	int nxt_idx=0, edges_count=0;
	int src_idx=0, tgt_idx=0;
	uint64_t print_val = 0;
	int rest_src_idx=0, rest_tgt_idx=0, rest_host_count=0;
	uint64_t rest_val=0;
	char file_path[MAX_FILE_NAME_LEN];
	int non_dns_count = 1;

	//FILE *fp_fdeg, *fp_pdeg, *fp_bdeg;
	//FILE *fp_fdeg_l2f, *fp_pdeg_l2f, *fp_bdeg_l2f;
	//FILE *fp_fdeg_f2l, *fp_pdeg_f2l, *fp_bdeg_f2l;
	FILE *fp_pdeg_l2f, *fp_bdeg_l2f;
	FILE *fp_pdeg_f2l, *fp_bdeg_f2l;

	// /* 1. sort by flow degree */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_FDEG_FILE, drohn_dir);
	// if((fp_fdeg = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening fdeg json file.");
	// }
	// TOP_K_JSON(fp_fdeg, edge_sort_fdeg,
	// 			edge->intvl_flows_l2f+edge->intvl_flows_f2l);
	// /* 2. sort by pkt degree */
	// snprintf(file_path, sizeof(file_path),
	// 	"%s/dashboard/"JSON_PDEG_FILE, drohn_dir);
	// if((fp_pdeg = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening pdeg json file.");
	// }
	// TOP_K_JSON(fp_pdeg, edge_sort_pdeg, 
	// 			edge->intvl_pkts_l2f+edge->intvl_pkts_f2l);
	// /* 3. sort by byte degree */
	// snprintf(file_path, sizeof(file_path),
	// 	"%s/dashboard/"JSON_BDEG_FILE, drohn_dir);
	// if((fp_bdeg = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening bdeg json file.");
	// }
	// TOP_K_JSON(fp_bdeg, edge_sort_bdeg, 
	// 			edge->intvl_bytes_l2f+edge->intvl_bytes_f2l);
	// /* 4. sort by l2f flow degree */
	// snprintf(file_path, sizeof(file_path),
	// 	"%s/dashboard/"JSON_FDEG_L2F_FILE, drohn_dir);
	// if((fp_fdeg_l2f = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening fdeg_l2f json file.");
	// }
	// TOP_K_JSON(fp_fdeg_l2f, edge_sort_fl2fdeg, 
	// 			edge->intvl_flows_l2f);

	/* 5. sort by l2f pkt degree */
	non_dns_count = 1;
	snprintf(file_path, sizeof(file_path),
		"%s/dashboard/"JSON_PDEG_L2F_FILE, drohn_dir);
	if((fp_pdeg_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pdeg_l2f json file.");
	}
	TOP_K_JSON(fp_pdeg_l2f, edge_sort_pl2fdeg, 
				edge->intvl_pkts_l2f);
	/* 6. sort by l2f byte degree */
	non_dns_count = 1;
	snprintf(file_path, sizeof(file_path),
		"%s/dashboard/"JSON_BDEG_L2F_FILE, drohn_dir);
	if((fp_bdeg_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bdeg json file.");
	}
	TOP_K_JSON(fp_bdeg_l2f, edge_sort_bl2fdeg, 
				edge->intvl_bytes_l2f);
	// /* 7. sort by f2l flow degree */
	// snprintf(file_path, sizeof(file_path),
	// 	"%s/dashboard/"JSON_FDEG_F2L_FILE, drohn_dir);
	// if((fp_fdeg_f2l = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening fdeg_f2l json file.");
	// }
	// TOP_K_JSON(fp_fdeg_f2l, edge_sort_ff2ldeg, 
	// 			edge->intvl_flows_f2l);
	/* 8. sort by f2l pkt degree */
	non_dns_count = 1;
	snprintf(file_path, sizeof(file_path),
		"%s/dashboard/"JSON_PDEG_F2L_FILE, drohn_dir);
	if((fp_pdeg_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pdeg_f2l json file.");
	}
	TOP_K_JSON(fp_pdeg_f2l, edge_sort_pf2ldeg, 
				edge->intvl_pkts_f2l);
	/* 9. sort by f2l byte degree */
	non_dns_count = 1;
	snprintf(file_path, sizeof(file_path),
		"%s/dashboard/"JSON_BDEG_F2L_FILE, drohn_dir);
	if((fp_bdeg_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bdeg json file.");
	}
	TOP_K_JSON(fp_bdeg_f2l, edge_sort_bf2ldeg,
				edge->intvl_bytes_f2l);
}

void gen_overview_json(char *drohn_dir)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	//printf("S %s\n", __FUNCTION__);
	struct lh_stat *lh, *tmp_lh;

	/* Node count */
	// int hosts_nc, flows_nc, flows_l2f_nc, flows_f2l_nc;
	// int pkts_nc, pkts_l2f_nc, pkts_f2l_nc;
	// int bytes_nc, bytes_l2f_nc, bytes_f2l_nc;

	// int hosts_lt, flows_lt, flows_l2f_lt, flows_f2l_lt;
	// int pkts_lt, pkts_l2f_lt, pkts_f2l_lt;
	// int bytes_lt, bytes_l2f_lt, bytes_f2l_lt;
	int hosts_nc;
	int pkts_l2f_nc, pkts_f2l_nc;
	int bytes_l2f_nc, bytes_f2l_nc;

	int hosts_lt;
	int pkts_l2f_lt, pkts_f2l_lt;
	int bytes_l2f_lt, bytes_f2l_lt;

	char file_path[MAX_FILE_NAME_LEN];
	char mac_addr[18];
	char ip_addr[16];

	FILE *fp_hosts;
	// FILE *fp_flows, *fp_flows_l2f, *fp_flows_f2l;
	// FILE *fp_pkts, *fp_pkts_l2f, *fp_pkts_f2l;
	// FILE *fp_bytes, *fp_bytes_l2f, *fp_bytes_f2l;
	FILE *fp_pkts_l2f, *fp_pkts_f2l;
	FILE *fp_bytes_l2f, *fp_bytes_f2l;

	/* Build JSON files overview graphs */
	/* 1. hosts */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_HOSTS_FILE, drohn_dir);
	if((fp_hosts = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening hosts json file.");
	}
	// /* 2. flows */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_FLOWS_FILE, drohn_dir);
	// if((fp_flows = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows json file.");
	// }
	// /* 3. flows_l2f */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_FLOWS_L2F_FILE, drohn_dir);
	// if((fp_flows_l2f = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows_l2f json file.");
	// }
	// /* 4. flows_f2l */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_FLOWS_F2L_FILE, drohn_dir);
	// if((fp_flows_f2l = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows_f2l json file.");
	// }
	// /* 5. pkts */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_PKTS_FILE, drohn_dir);
	// if((fp_pkts = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening pkts json file.");
	// }
	/* 6. pkts_l2f */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_PKTS_L2F_FILE, drohn_dir);
	if((fp_pkts_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pkts_l2f json file.");
	}
	/* 7. pkts_f2l */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_PKTS_F2L_FILE, drohn_dir);
	if((fp_pkts_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pkts_f2l json file.");
	}
	// /* 8. bytes */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_BYTES_FILE, drohn_dir);
	// if((fp_bytes = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening bytes json file.");
	// }
	/* 9. bytes_l2f */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_BYTES_L2F_FILE, drohn_dir);
	if((fp_bytes_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bytes_l2f json file.");
	}
	/* 10. bytes_f2l */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_BYTES_F2L_FILE, drohn_dir);
	if((fp_bytes_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bytes_f2l json file.");
	}

	fprintf(fp_hosts, "{\"nodes\":[\n");
	// fprintf(fp_flows, "{\"nodes\":[\n");
	// fprintf(fp_flows_l2f, "{\"nodes\":[\n");
	// fprintf(fp_flows_f2l, "{\"nodes\":[\n");
	// fprintf(fp_pkts, "{\"nodes\":[\n");
	fprintf(fp_pkts_l2f, "{\"nodes\":[\n");
	fprintf(fp_pkts_f2l, "{\"nodes\":[\n");
	// fprintf(fp_bytes, "{\"nodes\":[\n");
	fprintf(fp_bytes_l2f, "{\"nodes\":[\n");
	fprintf(fp_bytes_f2l, "{\"nodes\":[\n");

	/* for nodes */
	hosts_nc = 0;
	// flows_nc = 0;
	// flows_l2f_nc = 0;
	// flows_f2l_nc = 0;
	// pkts_nc = 0;
	pkts_l2f_nc = 0;
	pkts_f2l_nc = 0;
	// bytes_nc = 0;
	bytes_l2f_nc = 0;
	bytes_f2l_nc = 0;
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		snprintf(mac_addr, sizeof(mac_addr),
					"%02x:%02x:%02x:%02x:%02x:%02x",
					lh->lh_mac[0],lh->lh_mac[1],lh->lh_mac[2],
					lh->lh_mac[3],lh->lh_mac[4],lh->lh_mac[5]);
		snprintf(ip_addr, sizeof(ip_addr),
					"%u.%u.%u.%u", NIPQUAD(lh->c_ip));
		OVERVIEW_JSON_NODE(fp_hosts, lh->ci_hosts,
							lh->lid, lh->host_name, hosts_nc,  
							mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_flows, lh->ci_flows_l2f+lh->ci_flows_f2l, 
		// 					lh->lid, lh->host_name, flows_nc,  
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_flows_l2f, lh->ci_flows_l2f, 
		// 					lh->lid, lh->host_name, flows_l2f_nc,  
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_flows_f2l, lh->ci_flows_f2l, 
		// 					lh->lid, lh->host_name, flows_f2l_nc,  
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_pkts, lh->ci_pkts_l2f+lh->ci_pkts_f2l, 
		// 					lh->lid, lh->host_name, pkts_nc,  
		// 					mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_pkts_l2f, lh->ci_pkts_l2f, 
							lh->lid, lh->host_name, pkts_l2f_nc,  
							mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_pkts_f2l, lh->ci_pkts_f2l, 
							lh->lid, lh->host_name, pkts_f2l_nc,  
							mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_bytes, lh->ci_bytes_l2f+lh->ci_bytes_f2l, 
		// 					lh->lid, lh->host_name, bytes_nc,  
		// 					mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_bytes_l2f, lh->ci_bytes_l2f, 
							lh->lid, lh->host_name, bytes_l2f_nc,  
							mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_bytes_f2l, lh->ci_bytes_f2l, 
							lh->lid, lh->host_name, bytes_f2l_nc,  
							mac_addr, ip_addr);
	}
	fprintf(fp_hosts, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows_l2f, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows_f2l, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_pkts, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_pkts_l2f, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_pkts_f2l, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_bytes, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_bytes_l2f, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_bytes_f2l, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	/* for links */
	hosts_lt = 0;
	// flows_lt = 0;
	// flows_l2f_lt = 0;
	// flows_f2l_lt = 0;
	// pkts_lt = 0;
	pkts_l2f_lt = 0;
	pkts_f2l_lt = 0;
	// bytes_lt = 0;
	bytes_l2f_lt = 0;
	bytes_f2l_lt = 0;
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		OVERVIEW_JSON_LINK(fp_hosts, lh->ci_hosts, hosts_nc, hosts_lt);
		// OVERVIEW_JSON_LINK(fp_flows, lh->ci_flows_l2f+lh->ci_flows_f2l, 
		// 					flows_nc, flows_lt);
		// OVERVIEW_JSON_LINK(fp_flows_l2f, lh->ci_flows_l2f, 
		// 					flows_l2f_nc, flows_l2f_lt);
		// OVERVIEW_JSON_LINK(fp_flows_f2l, lh->ci_flows_f2l, 
		// 					flows_f2l_nc, flows_f2l_lt);
		// OVERVIEW_JSON_LINK(fp_pkts, lh->ci_pkts_l2f+lh->ci_pkts_f2l, 
		// 					pkts_nc, pkts_lt);
		OVERVIEW_JSON_LINK(fp_pkts_l2f, lh->ci_pkts_l2f, 
							pkts_l2f_nc, pkts_l2f_lt);
		OVERVIEW_JSON_LINK(fp_pkts_f2l, lh->ci_pkts_f2l, 
							pkts_f2l_nc, pkts_f2l_lt);
		// OVERVIEW_JSON_LINK_LLU(fp_bytes, lh->ci_bytes_l2f+lh->ci_bytes_f2l, 
		// 					bytes_nc, bytes_lt);
		OVERVIEW_JSON_LINK_LLU(fp_bytes_l2f, lh->ci_bytes_l2f, 
							bytes_l2f_nc, bytes_l2f_lt);
		OVERVIEW_JSON_LINK_LLU(fp_bytes_f2l, lh->ci_bytes_f2l, 
							bytes_f2l_nc, bytes_f2l_lt);
	}
	fclose(fp_hosts);
	// fclose(fp_flows);
	// fclose(fp_flows_l2f);
	// fclose(fp_flows_f2l);
	// fclose(fp_pkts);
	fclose(fp_pkts_l2f);
	fclose(fp_pkts_f2l);
	// fclose(fp_bytes);
	fclose(fp_bytes_l2f);
	fclose(fp_bytes_f2l);
}
void gen_avg_overview_json(char *drohn_dir)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	//printf("S %s\n", __FUNCTION__);
	struct lh_stat *lh, *tmp_lh;

	/* Node count */
	// int hosts_nc, flows_nc, flows_l2f_nc, flows_f2l_nc;
	// int pkts_nc, pkts_l2f_nc, pkts_f2l_nc;
	// int bytes_nc, bytes_l2f_nc, bytes_f2l_nc;
	int hosts_nc;
	int pkts_l2f_nc, pkts_f2l_nc;
	int bytes_l2f_nc, bytes_f2l_nc;

	// int hosts_lt, flows_lt, flows_l2f_lt, flows_f2l_lt;
	// int pkts_lt, pkts_l2f_lt, pkts_f2l_lt;
	// int bytes_lt, bytes_l2f_lt, bytes_f2l_lt;
	int hosts_lt;
	int pkts_l2f_lt, pkts_f2l_lt;
	int bytes_l2f_lt, bytes_f2l_lt;

	char file_path[MAX_FILE_NAME_LEN];
	char mac_addr[18];
	char ip_addr[16];

	FILE *fp_hosts;
	// FILE *fp_flows, *fp_flows_l2f, *fp_flows_f2l;
	// FILE *fp_pkts, *fp_pkts_l2f, *fp_pkts_f2l;
	// FILE *fp_bytes, *fp_bytes_l2f, *fp_bytes_f2l;
	FILE *fp_pkts_l2f, *fp_pkts_f2l;
	FILE *fp_bytes_l2f, *fp_bytes_f2l;

	/* Build JSON files overview graphs */
	/* 1. hosts */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_AVG_HOSTS_FILE, drohn_dir);
	if((fp_hosts = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening hosts json file.");
	}
	// /* 2. flows */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_AVG_FLOWS_FILE, drohn_dir);
	// if((fp_flows = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows json file.");
	// }
	// /* 3. flows_l2f */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_AVG_FLOWS_L2F_FILE, drohn_dir);
	// if((fp_flows_l2f = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows_l2f json file.");
	// }
	// /* 4. flows_f2l */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_AVG_FLOWS_F2L_FILE, drohn_dir);
	// if((fp_flows_f2l = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening flows_f2l json file.");
	// }
	// /* 5. pkts */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_AVG_PKTS_FILE, drohn_dir);
	// if((fp_pkts = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening pkts json file.");
	// }
	/* 6. pkts_l2f */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_AVG_PKTS_L2F_FILE, drohn_dir);
	if((fp_pkts_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pkts_l2f json file.");
	}
	/* 7. pkts_f2l */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_AVG_PKTS_F2L_FILE, drohn_dir);
	if((fp_pkts_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening pkts_f2l json file.");
	}
	// /* 8. bytes */
	// snprintf(file_path, sizeof(file_path),
	// 		"%s/dashboard/"JSON_AVG_BYTES_FILE, drohn_dir);
	// if((fp_bytes = fopen(file_path, "w")) == NULL){
	// 	die_with_error("Error in opening bytes json file.");
	// }
	/* 9. bytes_l2f */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_AVG_BYTES_L2F_FILE, drohn_dir);
	if((fp_bytes_l2f = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bytes_l2f json file.");
	}
	/* 10. bytes_f2l */
	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"JSON_AVG_BYTES_F2L_FILE, drohn_dir);
	if((fp_bytes_f2l = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening bytes_f2l json file.");
	}

	fprintf(fp_hosts, "{\"nodes\":[\n");
	// fprintf(fp_flows, "{\"nodes\":[\n");
	// fprintf(fp_flows_l2f, "{\"nodes\":[\n");
	// fprintf(fp_flows_f2l, "{\"nodes\":[\n");
	// fprintf(fp_pkts, "{\"nodes\":[\n");
	fprintf(fp_pkts_l2f, "{\"nodes\":[\n");
	fprintf(fp_pkts_f2l, "{\"nodes\":[\n");
	// fprintf(fp_bytes, "{\"nodes\":[\n");
	fprintf(fp_bytes_l2f, "{\"nodes\":[\n");
	fprintf(fp_bytes_f2l, "{\"nodes\":[\n");

	/* for nodes */
	hosts_nc = 0;
	// flows_nc = 0;
	// flows_l2f_nc = 0;
	// flows_f2l_nc = 0;
	// pkts_nc = 0;
	pkts_l2f_nc = 0;
	pkts_f2l_nc = 0;
	// bytes_nc = 0;
	bytes_l2f_nc = 0;
	bytes_f2l_nc = 0;
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		snprintf(mac_addr, sizeof(mac_addr),
					"%02x:%02x:%02x:%02x:%02x:%02x",
					lh->lh_mac[0],lh->lh_mac[1],lh->lh_mac[2],
					lh->lh_mac[3],lh->lh_mac[4],lh->lh_mac[5]);
		snprintf(ip_addr, sizeof(ip_addr),
					"%u.%u.%u.%u", NIPQUAD(lh->c_ip));
		OVERVIEW_JSON_NODE_F(fp_hosts, lh->ai_hosts,
							lh->lid, lh->host_name, hosts_nc, 
							mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE_F(fp_flows, lh->ai_flows_l2f+lh->ai_flows_f2l, 
		// 					lh->lid, lh->host_name, flows_nc, 
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE_F(fp_flows_l2f, lh->ai_flows_l2f, 
		// 					lh->lid, lh->host_name, flows_l2f_nc, 
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE_F(fp_flows_f2l, lh->ai_flows_f2l, 
		// 					lh->lid, lh->host_name, flows_f2l_nc, 
		// 					mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE_F(fp_pkts, lh->ai_pkts_l2f+lh->ai_pkts_f2l, 
		// 					lh->lid, lh->host_name, pkts_nc, 
		// 					mac_addr, ip_addr);
		OVERVIEW_JSON_NODE_F(fp_pkts_l2f, lh->ai_pkts_l2f, 
							lh->lid, lh->host_name, pkts_l2f_nc, 
							mac_addr, ip_addr);
		OVERVIEW_JSON_NODE_F(fp_pkts_f2l, lh->ai_pkts_f2l, 
							lh->lid, lh->host_name, pkts_f2l_nc, 
							mac_addr, ip_addr);
		// OVERVIEW_JSON_NODE(fp_bytes, lh->ai_bytes_l2f+lh->ai_bytes_f2l, 
		// 					lh->lid, lh->host_name, bytes_nc, 
		// 					mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_bytes_l2f, lh->ai_bytes_l2f, 
							lh->lid, lh->host_name, bytes_l2f_nc, 
							mac_addr, ip_addr);
		OVERVIEW_JSON_NODE(fp_bytes_f2l, lh->ai_bytes_f2l, 
							lh->lid, lh->host_name, bytes_f2l_nc, 
							mac_addr, ip_addr);
	}
	
	fprintf(fp_hosts, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows_l2f, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_flows_f2l, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_pkts, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_pkts_l2f, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_pkts_f2l, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	// fprintf(fp_bytes, "{\"name\":\"Internet\","
	// 		"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_bytes_l2f, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	fprintf(fp_bytes_f2l, "{\"name\":\"Internet\","
			"\"mac\":\"N/A\",\"ip\":\"N/A\"}\n],\n\"links\":[\n");
	/* for links */
	hosts_lt = 0;
	// flows_lt = 0;
	// flows_l2f_lt = 0;
	// flows_f2l_lt = 0;
	// pkts_lt = 0;
	pkts_l2f_lt = 0;
	pkts_f2l_lt = 0;
	// bytes_lt = 0;
	bytes_l2f_lt = 0;
	bytes_f2l_lt = 0;
	HASH_ITER(hh, lh_hhead, lh, tmp_lh){
		OVERVIEW_JSON_LINK_2F(fp_hosts, lh->ai_hosts, hosts_nc, hosts_lt);
		// OVERVIEW_JSON_LINK_2F(fp_flows, lh->ai_flows_l2f+lh->ai_flows_f2l, 
		// 					flows_nc, flows_lt);
		// OVERVIEW_JSON_LINK_2F(fp_flows_l2f, lh->ai_flows_l2f, 
		// 					flows_l2f_nc, flows_l2f_lt);
		// OVERVIEW_JSON_LINK_2F(fp_flows_f2l, lh->ai_flows_f2l, 
		// 					flows_f2l_nc, flows_f2l_lt);
		// OVERVIEW_JSON_LINK_2F(fp_pkts, lh->ai_pkts_l2f+lh->ai_pkts_f2l, 
		// 					pkts_nc, pkts_lt);
		OVERVIEW_JSON_LINK_2F(fp_pkts_l2f, lh->ai_pkts_l2f, 
							pkts_l2f_nc, pkts_l2f_lt);
		OVERVIEW_JSON_LINK_2F(fp_pkts_f2l, lh->ai_pkts_f2l, 
							pkts_f2l_nc, pkts_f2l_lt);
		// OVERVIEW_JSON_LINK_LLU(fp_bytes, lh->ai_bytes_l2f+lh->ai_bytes_f2l, 
		// 					bytes_nc, bytes_lt);
		OVERVIEW_JSON_LINK_LLU(fp_bytes_l2f, lh->ai_bytes_l2f, 
							bytes_l2f_nc, bytes_l2f_lt);
		OVERVIEW_JSON_LINK_LLU(fp_bytes_f2l, lh->ai_bytes_f2l, 
							bytes_f2l_nc, bytes_f2l_lt);
	}
	fclose(fp_hosts);
	// fclose(fp_flows);
	// fclose(fp_flows_l2f);
	// fclose(fp_flows_f2l);
	// fclose(fp_pkts);
	fclose(fp_pkts_l2f);
	fclose(fp_pkts_f2l);
	// fclose(fp_bytes);
	fclose(fp_bytes_l2f);
	fclose(fp_bytes_f2l);
}

void gen_timestamp(char *drohn_dir, struct timeval start)
{
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	//printf("S %s\n", __FUNCTION__);
	char file_path[MAX_FILE_NAME_LEN];
	FILE *fp;

	snprintf(file_path, sizeof(file_path),
			"%s/dashboard/"TIMESTAMP_FILE, drohn_dir);
	if((fp = fopen(file_path, "w")) == NULL){
		die_with_error("Error in opening timestamp file.");
	}
	fprintf(fp, "%d", start.tv_sec);
	fclose(fp);
}