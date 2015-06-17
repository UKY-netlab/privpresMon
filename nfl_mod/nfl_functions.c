#include <linux/file.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/atomic.h>
#include "crc.h"
#include "nfl.h"
#include "nfl_functions.h"

/* get_hash_crc32(): crc32-based hash function */
uint32_t get_hash_crc32(struct ipflowkey *flowkey)
{
	uint32_t hash = 0;
	#define X(type, name) \
		hash = crc32(hash, sizeof(type), &flowkey->name); 
	LIST_OF_FLOWKEY_FIELDS
	#undef X
	return hash;
}

/* flowkey_cmp(): compare keys of two flows */
int8_t flowkey_cmp(struct ipflowkey *a, struct ipflowkey *b)
{
	int8_t ret = 0;
	#define X(type, name) \
		if (a->name != b->name) ret = -1; 
	LIST_OF_FLOWKEY_FIELDS
	#undef X
	return ret;
}

/* Calcute time diff of two struct timeval variables */
uint32_t get_time_offset(struct timeval sml, struct timeval lrg)
{
	uint32_t usec_diff = (lrg.tv_sec-sml.tv_sec)*1000000;
	usec_diff += (lrg.tv_usec>=sml.tv_usec ? 
			lrg.tv_usec-sml.tv_usec 
			: sml.tv_usec-lrg.tv_usec);
	return usec_diff;
}

/* Swap two flow lists for exporting */
void ptr_swap(struct ipflow_exp_stat **p1, struct ipflow_exp_stat **p2)
{
	struct ipflow_exp_stat *tmp = *p1;
	*p1 = *p2;
	*p2 = tmp;
}

/* Change DNS mask port */
int new_dns_mask(int old_mask)
{
	if(old_mask == DNS_MASK_PORT_END){
		return DNS_MASK_PORT_START;
	}
	return old_mask+1;
}

