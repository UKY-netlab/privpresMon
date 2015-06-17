/*
 * nflc_utils.h
 *
 * By Xuzi Zhou
 */

#ifndef NFLC_UTILS_H
#define NFLC_UTILS_H

#include <linux/types.h>
#include <stdlib.h>
#include <stdint.h>
#include "nflc.h"

#define COPY_TIMEVAL(time_new, time_orig)	\
do{											\
	time_new.tv_sec = time_orig.tv_sec;		\
	time_new.tv_usec = time_orig.tv_sec;	\
}while(0)

#define INIT_MAC(left)	\
do{							\
	left[0] = 0;			\
	left[1] = 0;			\
	left[2] = 0;			\
	left[3] = 0;			\
	left[4] = 0;			\
	left[5] = 0;			\
}while(0)

#define COPY_MAC(left, right)	\
do{								\
	left[0] = right[0];			\
	left[1] = right[1];			\
	left[2] = right[2];			\
	left[3] = right[3];			\
	left[4] = right[4];			\
	left[5] = right[5];			\
}while(0)

#define INIT_CFLOW(cf, f_exp)							\
do{														\
	cf->seq = f_exp->seq;								\
	cf->flow_key.protocol = f_exp->flow_key.protocol;	\
	cf->flow_key.padding1 = 0;							\
	cf->flow_key.padding2 = 0;							\
	cf->flow_key.sport = f_exp->flow_key.sport;			\
	cf->flow_key.dport = f_exp->flow_key.dport;			\
	cf->flow_key.saddr = f_exp->flow_key.saddr;			\
	cf->flow_key.daddr = f_exp->flow_key.daddr;			\
	cf->export_count = f_exp->export_count;				\
	COPY_TIMEVAL(cf->start, f_exp->start);				\
	COPY_TIMEVAL(cf->intvl_start, f_exp->intvl_start);	\
	COPY_TIMEVAL(cf->end, f_exp->end);					\
	cf->pkts = f_exp->pkts;								\
	cf->intvl_pkts = f_exp->intvl_pkts;					\
	cf->bytes = f_exp->bytes;							\
	cf->intvl_bytes = f_exp->intvl_bytes;				\
}while(0)

#define INIT_RFLOW(rf, f_exp, active)					\
do{														\
	rf->seq = f_exp->seq;								\
	rf->flow_key.protocol = f_exp->flow_key.protocol;	\
	rf->flow_key.padding1 = 0;							\
	rf->flow_key.padding2 = 0;							\
	rf->flow_key.sport = f_exp->flow_key.sport;			\
	rf->flow_key.dport = f_exp->flow_key.dport;			\
	rf->flow_key.saddr = f_exp->flow_key.saddr;			\
	rf->flow_key.daddr = f_exp->flow_key.daddr;			\
	rf->is_active = active;								\
	rf->export_count = f_exp->export_count;				\
	COPY_TIMEVAL(rf->start, f_exp->start);				\
	COPY_TIMEVAL(rf->end, f_exp->end);					\
	rf->pkts = f_exp->pkts;								\
	rf->bytes = f_exp->bytes;							\
}while(0)

#define UPDATE_RFLOW(rf, f_exp, active)					\
do{														\
	rf->is_active = active;								\
	rf->export_count = f_exp->export_count;				\
	COPY_TIMEVAL(rf->end, f_exp->end);					\
	rf->pkts = f_exp->pkts;								\
	rf->bytes = f_exp->bytes;							\
}while(0)

#define INIT_EDGE_HASH_L2F(edge,key,d,p,b,ip,ib,pr)	\
do{													\
	COPY_MAC(edge->edge_key.lh_mac, key.lh_mac);	\
	edge->edge_key.faddr = key.faddr;				\
	edge->prot_bitmap = 0;							\
	for(i=0; i<3; i++){								\
		edge->ports[i].port=0;						\
		edge->ports[i].cnt=0;}						\
	edge->max_dur = d;								\
	edge->flows_l2f = 1;							\
	edge->flows_f2l = 0;							\
	edge->pkts_l2f = p;								\
	edge->pkts_f2l = 0;								\
	edge->bytes_l2f = b;							\
	edge->bytes_f2l = 0;							\
	if(ip>0){										\
		edge->intvl_flows_l2f = 1;					\
		edge->intvl_pkts_l2f = ip;					\
		edge->intvl_bytes_l2f = ib;					\
	} else{											\
		edge->intvl_flows_l2f = 0;					\
		edge->intvl_pkts_l2f = 0;					\
		edge->intvl_bytes_l2f = 0;					\
	}												\
	edge->intvl_flows_f2l = 0;						\
	edge->intvl_pkts_f2l = 0;						\
	edge->intvl_bytes_f2l = 0;						\
	if(pr==IPPROTO_TCP) edge->prot_bitmap|=1;		\
	if(pr==IPPROTO_UDP) edge->prot_bitmap|=2;		\
	if(pr==IPPROTO_ICMP) edge->prot_bitmap|=4;		\
}while(0)

#define INIT_EDGE_HASH_F2L(edge,key,d,p,b,ip,ib,pr)	\
do{													\
	COPY_MAC(edge->edge_key.lh_mac, key.lh_mac);	\
	edge->edge_key.faddr = key.faddr;				\
	edge->prot_bitmap = 0;							\
	for(i=0; i<3; i++){								\
		edge->ports[i].port=0;						\
		edge->ports[i].cnt=0;}						\
	edge->max_dur = d;								\
	edge->flows_l2f = 0;							\
	edge->flows_f2l = 1;							\
	edge->pkts_l2f = 0;								\
	edge->pkts_f2l = p;								\
	edge->bytes_l2f = 0;							\
	edge->bytes_f2l = b;							\
	if(ip>0){										\
		edge->intvl_flows_f2l = 1;					\
		edge->intvl_pkts_f2l = ip;					\
		edge->intvl_bytes_f2l = ib;					\
	} else{											\
		edge->intvl_flows_f2l = 0;					\
		edge->intvl_pkts_f2l = 0;					\
		edge->intvl_bytes_f2l = 0;					\
	}												\
	edge->intvl_flows_l2f = 0;						\
	edge->intvl_pkts_l2f = 0;						\
	edge->intvl_bytes_l2f = 0;						\
	if(pr==IPPROTO_TCP) edge->prot_bitmap|=1;		\
	if(pr==IPPROTO_UDP) edge->prot_bitmap|=2;		\
	if(pr==IPPROTO_ICMP) edge->prot_bitmap|=4;		\
}while(0)

#define UPDATE_EDGE_HASH_L2F(edge,d,p,b,ip,ib,pr)	\
do{													\
	edge->flows_l2f += 1;							\
	edge->pkts_l2f += p;							\
	edge->bytes_l2f += b;							\
	if(ip>0){										\
		edge->intvl_flows_l2f += 1;					\
		edge->intvl_pkts_l2f += ip;					\
		edge->intvl_bytes_l2f += ib;}				\
	if(pr==IPPROTO_TCP) edge->prot_bitmap|=1;		\
	if(pr==IPPROTO_UDP) edge->prot_bitmap|=2;		\
	if(pr==IPPROTO_ICMP) edge->prot_bitmap|=4;		\
	if(d>edge->max_dur) edge->max_dur=d;			\
}while(0)

#define UPDATE_EDGE_HASH_F2L(edge,d,p,b,ip,ib,pr)	\
do{													\
	edge->flows_f2l += 1;							\
	edge->pkts_f2l += p;							\
	edge->bytes_f2l += b;							\
	if(ip>0){										\
		edge->intvl_flows_f2l += 1;					\
		edge->intvl_pkts_f2l += ip;					\
		edge->intvl_bytes_f2l += ib;}				\
	if(pr==IPPROTO_TCP) edge->prot_bitmap|=1;		\
	if(pr==IPPROTO_UDP) edge->prot_bitmap|=2;		\
	if(pr==IPPROTO_ICMP) edge->prot_bitmap|=4;		\
	if(d>edge->max_dur) edge->max_dur=d;			\
}while(0)

#define UPDATE_EDGE_STAT_L2F(p, b, ip, ib)			\
do{													\
	estat.flows_l2f += 1;							\
	estat.pkts_l2f += p;							\
	estat.bytes_l2f += b;							\
	if(ip > 0){										\
		estat.intvl_flows_total += 1;				\
		estat.intvl_flows_l2f += 1;					\
		estat.intvl_pkts_l2f += ip;					\
		estat.intvl_bytes_l2f += ib;}				\
}while(0)

#define UPDATE_EDGE_STAT_F2L(p, b, ip, ib)			\
do{													\
	estat.flows_f2l += 1;							\
	estat.pkts_f2l += p;							\
	estat.bytes_f2l += b;							\
	if(ip > 0){										\
		estat.intvl_flows_total += 1;				\
		estat.intvl_flows_f2l += 1;					\
		estat.intvl_pkts_f2l += ip;					\
		estat.intvl_bytes_f2l += ib;}				\
}while(0)

#define ADD_EDGE_PORT_DATA(edge, pidx, phash)			\
do{														\
	if(edge != NULL){									\
		if(edge->prot_bitmap!=4){						\
			for(i=0; i<3; i++){							\
				int port = pidx[i];						\
				int cnt = phash[port];					\
				edge->ports[i].port=port;				\
				edge->ports[i].cnt=cnt;} } }			\
}while(0)

#define UPDATE_PORT_HASH(p)				\
do{										\
	port_lvl0[p] += 1;					\
	bits = p/PORT_LVL_R;				\
	aidx = bits/PORT_LVL_R;				\
	bidx = bits%PORT_LVL_R;				\
	port_lvl1[aidx] |= (1<<bidx);		\
	bits = aidx;						\
	aidx = bits/PORT_LVL_R;				\
	bidx = bits%PORT_LVL_R;				\
	port_lvl2[aidx] |= (1<<bidx);		\
}while(0)

#define GET_TOP_PORTS(tp)											\
do{																	\
	for(i=0; i<PORT_LVL_R; i++){									\
	if(port_lvl2[i]!=0){											\
		for(j=0; j<PORT_LVL_R; j++){								\
		if((port_lvl2[i] & (1<<j)) != 0){							\
			ip1 = i*PORT_LVL_R+j;									\
			for(k=0; k<PORT_LVL_R; k++){							\
			if((port_lvl1[ip1] & (1<<k)) != 0){						\
				ip0 = PORT_LVL_R*(ip1*PORT_LVL_R+k);				\
				for(l=0; l<PORT_LVL_R; l++){						\
				ip0p=ip0+l;											\
				if(port_lvl0[ip0p]>0){								\
					if(port_lvl0[ip0p]>port_lvl0[tp[0]]){			\
						if(tp[1]>0)	tp[2]=tp[1]; 					\
						tp[1]=tp[0];								\
						tp[0]=ip0p;									\
					}else if(port_lvl0[ip0p]>port_lvl0[tp[1]]){		\
						tp[2]=tp[1];								\
						tp[1]=ip0p;									\
					}else if(port_lvl0[ip0p]>port_lvl0[tp[2]]){		\
						tp[2]=ip0p;}								\
	}}  }}  }}  }}													\
}while(0)

#define ZERO_LH_HASH_CURRENT_FIELDS(lh)		\
do{											\
	lh->c_hosts = 0;						\
	lh->c_flows_l2f = 0;					\
	lh->c_flows_f2l = 0;					\
	lh->c_pkts_l2f = 0;						\
	lh->c_pkts_f2l = 0;						\
	lh->c_bytes_l2f = 0;					\
	lh->c_bytes_f2l = 0;					\
	lh->ci_hosts = 0;						\
	lh->ci_flows_l2f = 0;					\
	lh->ci_flows_f2l = 0;					\
	lh->ci_pkts_l2f = 0;					\
	lh->ci_pkts_f2l = 0;					\
	lh->ci_bytes_l2f = 0;					\
	lh->ci_bytes_f2l = 0;					\
}while(0)

#define INIT_LH_HASH_L2F(lh, p, b, i_f, ip, ib)	\
do{												\
	lh->host_name[0] = '\0';					\
	lh->c_hosts = 0;							\
	lh->c_flows_l2f = 1;						\
	lh->c_flows_f2l = 0;						\
	lh->c_pkts_l2f = p;							\
	lh->c_pkts_f2l = 0;							\
	lh->c_bytes_l2f = b;						\
	lh->c_bytes_f2l = 0;						\
	lh->ci_hosts = 0;							\
	lh->ci_flows_l2f = i_f;						\
	lh->ci_flows_f2l = 0;						\
	lh->ci_pkts_l2f = ip;						\
	lh->ci_pkts_f2l = 0;						\
	lh->ci_bytes_l2f = ib;						\
	lh->ci_bytes_f2l = 0;						\
	lh->a_hosts = 1.0;							\
	lh->a_flows_l2f = 1.0;						\
	lh->a_flows_f2l = 0.0;						\
	lh->a_pkts_l2f = (double)p;					\
	lh->a_pkts_f2l = 0.0;						\
	lh->a_bytes_l2f = b;						\
	lh->a_bytes_f2l = 0;						\
	lh->ai_hosts = 1.0;							\
	lh->ai_flows_l2f = 1.0;						\
	lh->ai_flows_f2l = 0.0;						\
	lh->ai_pkts_l2f = (double)ip;				\
	lh->ai_pkts_f2l = 0.0;						\
	lh->ai_bytes_l2f = ib;						\
	lh->ai_bytes_f2l = 0;						\
	lh->flows_l2f = i_f;						\
	lh->flows_f2l = 0;							\
	lh->pkts_l2f = ip;							\
	lh->pkts_f2l = 0;							\
	lh->bytes_l2f = ib;							\
	lh->bytes_f2l = 0;							\
}while(0)

#define INIT_LH_HASH_F2L(lh, p, b, i_f, ip, ib)	\
do{												\
	lh->host_name[0] = '\0';					\
	lh->c_hosts = 0;							\
	lh->c_flows_l2f = 0;						\
	lh->c_flows_f2l = 1;						\
	lh->c_pkts_l2f = 0;							\
	lh->c_pkts_f2l = p;							\
	lh->c_bytes_l2f = 0;						\
	lh->c_bytes_f2l = b;						\
	lh->ci_hosts = 0;							\
	lh->ci_flows_l2f = 0;						\
	lh->ci_flows_f2l = i_f;						\
	lh->ci_pkts_l2f = 0;						\
	lh->ci_pkts_f2l = ip;						\
	lh->ci_bytes_l2f = 0;						\
	lh->ci_bytes_f2l = ib;						\
	lh->a_hosts = 1.0;							\
	lh->a_flows_l2f = 0.0;						\
	lh->a_flows_f2l = 1.0;						\
	lh->a_pkts_l2f = 0.0;						\
	lh->a_pkts_f2l = (double)p;					\
	lh->a_bytes_l2f = 0;						\
	lh->a_bytes_f2l = b;						\
	lh->ai_hosts = 1.0;							\
	lh->ai_flows_l2f = 0.0;						\
	lh->ai_flows_f2l = 1.0;						\
	lh->ai_pkts_l2f = 0.0;						\
	lh->ai_pkts_f2l = (double)ip;				\
	lh->ai_bytes_l2f = 0;						\
	lh->ai_bytes_f2l = ib;						\
	lh->flows_l2f = 0;							\
	lh->flows_f2l = i_f;						\
	lh->pkts_l2f = 0;							\
	lh->pkts_f2l = ip;							\
	lh->bytes_l2f = 0;							\
	lh->bytes_f2l = ib;							\
}while(0)

#define UPDATE_LH_HASH_L2F(lh, p, b, i_f, ip, ib)	\
do{													\
	lh->c_flows_l2f += 1;							\
	lh->c_pkts_l2f += p;							\
	lh->c_bytes_l2f += b;							\
	lh->ci_flows_l2f += i_f;						\
	lh->ci_pkts_l2f += ip;							\
	lh->ci_bytes_l2f += ib;							\
	lh->flows_l2f += i_f;							\
	lh->pkts_l2f += ip;								\
	lh->bytes_l2f += ib;							\
}while(0)

#define UPDATE_LH_HASH_F2L(lh, p, b, i_f, ip, ib)	\
do{													\
	lh->c_flows_f2l += 1;							\
	lh->c_pkts_f2l += p;							\
	lh->c_bytes_f2l += b;							\
	lh->ci_flows_f2l += i_f;						\
	lh->ci_pkts_f2l += ip;							\
	lh->ci_bytes_f2l += ib;							\
	lh->flows_f2l += i_f;							\
	lh->pkts_f2l += ip;								\
	lh->bytes_f2l += ib;							\
}while(0)

#define UPDATE_LH_HASH_EWMA(lh)								\
do{															\
	lh->a_hosts = (double)lh->c_hosts*EWMA_ALPHA			\
				+ lh->a_hosts*EWMA_ALPHA_COMP;				\
	lh->a_flows_l2f = (double)lh->c_flows_l2f*EWMA_ALPHA	\
					+ lh->a_flows_l2f*EWMA_ALPHA_COMP;		\
	lh->a_flows_f2l = (double)lh->c_flows_f2l*EWMA_ALPHA	\
					+ lh->a_flows_f2l*EWMA_ALPHA_COMP;		\
	lh->a_pkts_l2f = (double)lh->c_pkts_l2f*EWMA_ALPHA		\
					+ lh->a_pkts_l2f*EWMA_ALPHA_COMP;		\
	lh->a_pkts_f2l = (double)lh->c_pkts_f2l*EWMA_ALPHA		\
					+ lh->a_pkts_f2l*EWMA_ALPHA_COMP;		\
	lh->a_bytes_l2f = lh->c_bytes_l2f*EWMA_ALPHA			\
					+ lh->a_bytes_l2f*EWMA_ALPHA_COMP;		\
	lh->a_bytes_f2l = lh->c_bytes_f2l*EWMA_ALPHA			\
					+ lh->a_bytes_f2l*EWMA_ALPHA_COMP;		\
	lh->ai_hosts = (double)lh->ci_hosts*EWMA_ALPHA			\
				+ lh->ai_hosts*EWMA_ALPHA_COMP;				\
	lh->ai_flows_l2f = (double)lh->ci_flows_l2f*EWMA_ALPHA	\
					+ lh->ai_flows_l2f*EWMA_ALPHA_COMP;		\
	lh->ai_flows_f2l = (double)lh->ci_flows_f2l*EWMA_ALPHA	\
					+ lh->ai_flows_f2l*EWMA_ALPHA_COMP;		\
	lh->ai_pkts_l2f = (double)lh->ci_pkts_l2f*EWMA_ALPHA	\
					+ lh->ai_pkts_l2f*EWMA_ALPHA_COMP;		\
	lh->ai_pkts_f2l = (double)lh->ci_pkts_f2l*EWMA_ALPHA	\
					+ lh->ai_pkts_f2l*EWMA_ALPHA_COMP;		\
	lh->ai_bytes_l2f = lh->ci_bytes_l2f*EWMA_ALPHA			\
					+ lh->ai_bytes_l2f*EWMA_ALPHA_COMP;		\
	lh->ai_bytes_f2l = lh->ci_bytes_f2l*EWMA_ALPHA			\
					+ lh->ai_bytes_f2l*EWMA_ALPHA_COMP;		\
}while(0)

#define BUILD_MAGIC_HEAD(mh, count)		\
do{										\
	snprintf(mh.magic_word, 4, "nfl");	\
	mh.entry_count = count;				\
}while(0)

#define COPY_DNS_FIELDS(left, right)				\
do{													\
	left->ip = right->ip;							\
	left->ttl = right->ttl;							\
	strncpy(left->name, right->name, DNS_NAME_LEN);	\
}while(0)

#define COPY_ARP_FIELDS(left, right)		\
do{											\
	left->addr = right->addr;				\
	COPY_MAC(left->lh_mac, right->lh_mac);	\
}while(0)

#define COPY_LHSTAT_FIELDS(left, right)			\
do{												\
	COPY_MAC(left->lh_mac, right->lh_mac);		\
	strncpy(left->host_name, 					\
			right->host_name, 					\
			HOST_NAME_LEN);						\
	left->host_name[HOST_NAME_LEN] = '\0';		\
	left->lid = right->lid;						\
	left->c_ip = right->c_ip;					\
	left->c_hosts = right->c_hosts;				\
	left->c_flows_l2f = right->c_flows_l2f;		\
	left->c_flows_f2l = right->c_flows_f2l;		\
	left->c_pkts_l2f = right->c_pkts_l2f;		\
	left->c_pkts_f2l = right->c_pkts_f2l;		\
	left->c_bytes_l2f = right->c_bytes_l2f;		\
	left->c_bytes_f2l = right->c_bytes_f2l;		\
	left->ci_hosts = right->ci_hosts;			\
	left->ci_flows_l2f = right->ci_flows_l2f;	\
	left->ci_flows_f2l = right->ci_flows_f2l;	\
	left->ci_pkts_l2f = right->ci_pkts_l2f;		\
	left->ci_pkts_f2l = right->ci_pkts_f2l;		\
	left->ci_bytes_l2f = right->ci_bytes_l2f;	\
	left->ci_bytes_f2l = right->ci_bytes_f2l;	\
	left->a_hosts = right->a_hosts;				\
	left->a_flows_l2f = right->a_flows_l2f;		\
	left->a_flows_f2l = right->a_flows_f2l;		\
	left->a_pkts_l2f = right->a_pkts_l2f;		\
	left->a_pkts_f2l = right->a_pkts_f2l;		\
	left->a_bytes_l2f = right->a_bytes_l2f;		\
	left->a_bytes_f2l = right->a_bytes_f2l;		\
	left->ai_hosts = right->ai_hosts;			\
	left->ai_flows_l2f = right->ai_flows_l2f;	\
	left->ai_flows_f2l = right->ai_flows_f2l;	\
	left->ai_pkts_l2f = right->ai_pkts_l2f;		\
	left->ai_pkts_f2l = right->ai_pkts_f2l;		\
	left->ai_bytes_l2f = right->ai_bytes_l2f;	\
	left->ai_bytes_f2l = right->ai_bytes_f2l;	\
	left->flows_l2f = right->flows_l2f;			\
	left->flows_f2l = right->flows_f2l;			\
	left->pkts_l2f = right->pkts_l2f;			\
	left->pkts_f2l = right->pkts_f2l;			\
	left->bytes_l2f = right->bytes_l2f;			\
	left->bytes_f2l = right->bytes_f2l;			\
}while(0)

#define COPY_RF_FIELDS(left, right)						\
do{														\
	left->seq = right->seq;								\
	left->flow_key.protocol = right->flow_key.protocol;	\
	left->flow_key.padding1 = 0;						\
	left->flow_key.padding2 = 0;						\
	left->flow_key.sport = right->flow_key.sport;		\
	left->flow_key.dport = right->flow_key.dport;		\
	left->flow_key.saddr = right->flow_key.saddr;		\
	left->flow_key.daddr = right->flow_key.daddr;		\
	left->is_active = right->is_active;					\
	left->export_count = right->export_count;			\
	COPY_TIMEVAL(left->start, right->start);			\
	COPY_TIMEVAL(left->end, right->end);				\
	left->pkts = right->pkts;							\
	left->bytes = right->bytes;							\
}while(0)

#define OVERVIEW_JSON_LINK(fp, value, nc, lt)						\
do{																	\
	if(value > 0){													\
		fprintf(fp, "{\"source\":%d,\"target\":%d,\"value\":%lu}",	\
				lt, nc, value);										\
		if(++lt < nc){												\
			fprintf(fp, ",\n");										\
		} else{														\
			fprintf(fp, "\n]}\n");}}								\
}while(0)

#define OVERVIEW_JSON_LINK_LLU(fp, value, nc, lt)					\
do{																	\
	if(value > 0){													\
		fprintf(fp, "{\"source\":%d,\"target\":%d,\"value\":%llu}",	\
				lt, nc, value);										\
		if(++lt < nc){												\
			fprintf(fp, ",\n");										\
		} else{														\
			fprintf(fp, "\n]}\n");}}								\
}while(0)

#define OVERVIEW_JSON_LINK_2F(fp, value, nc, lt)					\
do{																	\
	if(value > 0.5){												\
		fprintf(fp,"{\"source\":%d,\"target\":%d,\"value\":%u} ",	\
				lt, nc, (uint32_t)(value+0.5));						\
		if(++lt < nc){												\
			fprintf(fp, ",\n");										\
		} else{														\
			fprintf(fp, "\n]}\n");}}								\
}while(0)

#define OVERVIEW_JSON_NODE(fp, value, lid, name, nc, macaddr, ipaddr)	\
do{																		\
	if(value > 0){														\
		fprintf(fp, "{\"name\":\"LID-%u %s\","							\
				"\"mac\":\"%s\",\"ip\":\"%s\"},\n", 					\
				lid, name, macaddr, ipaddr);							\
		nc += 1;}														\
}while(0)

#define OVERVIEW_JSON_NODE_F(fp, value, lid, name, nc, macaddr, ipaddr)	\
do{																		\
	if(value > 0.5){													\
		fprintf(fp, "{\"name\":\"LID-%u %s\","							\
				"\"mac\":\"%s\",\"ip\":\"%s\"},\n", 					\
				lid, name, macaddr, ipaddr);							\
		nc += 1;}														\
}while(0)

#define TOP_K_JSON(fp, sort_fn, value)									\
do{																		\
	nxt_idx = 0;														\
	edges_count = 0;													\
	rest_val = 0;														\
	rest_host_count = 0;												\
	HASH_SORT(edges_hhead, sort_fn);									\
	fprintf(fp, "{\"nodes\":[\n");										\
	INIT_MAC(tmp_mac);													\
	HASH_ITER(hh, edges_hhead, edge, tmp_edge){							\
		if(0 != maccmp(edge->edge_key.lh_mac, tmp_mac, 6)){				\
			if(rest_host_count>0){										\
				rest_tgt_idx = nxt_idx++;								\
				add_bglink(rest_src_idx,rest_tgt_idx,rest_val);			\
				fprintf(fp, "{\"name\":\"%d other hosts\","				\
						"\"mac\":\"N/A\",\"ip\":\"N/A\"},\n",			\
						rest_host_count);								\
				rest_host_count = 0;									\
				rest_val = 0;}											\
			COPY_MAC(tmp_mac,edge->edge_key.lh_mac);					\
			edges_count = 0;}											\
		if(edges_count < max_edges_num && value > 0){					\
			HASH_FIND(hh, lh_hhead, &(edge->edge_key.lh_mac), 			\
						6, tmp_lh);										\
			snprintf(mac_addr, sizeof(mac_addr),						\
					"%02x:%02x:%02x:%02x:%02x:%02x",					\
					tmp_lh->lh_mac[0],tmp_lh->lh_mac[1],				\
					tmp_lh->lh_mac[2],tmp_lh->lh_mac[3],				\
					tmp_lh->lh_mac[4],tmp_lh->lh_mac[5]);				\
			snprintf(ip_addr, sizeof(ip_addr),							\
					"%u.%u.%u.%u", NIPQUAD(tmp_lh->c_ip));				\
			if(edges_count==0){											\
				fprintf(fp, "{\"name\":\"LID-%u %s\","					\
						"\"mac\":\"%s\",\"ip\":\"%s\"},\n", 			\
						tmp_lh->lid, tmp_lh->host_name, 				\
						mac_addr, ip_addr);								\
				src_idx = nxt_idx++;									\
				rest_src_idx = src_idx;}								\
			HASH_FIND(hh, jf_hhead, &(edge->edge_key.faddr), 			\
						sizeof(__be32), tmp_jf);						\
			if(tmp_jf == NULL){											\
				HASH_FIND(hh, dns_hhead, &(edge->edge_key.faddr), 		\
							sizeof(__be32), tmp_dns);					\
				if(if_conf.resolve_sites == 1){								\
					if(tmp_dns == NULL){									\
						fprintf(fp, "{\"name\":\"%u.%u.%u.%u\","			\
							"\"mac\":\"N/A\",\"ip\":\"%u.%u.%u.%u\"},\n",	\
							NIPQUAD(edge->edge_key.faddr),					\
							NIPQUAD(edge->edge_key.faddr));}				\
					else{													\
						fprintf(fp, "{\"name\":\"%s\","						\
							"\"mac\":\"N/A\",\"ip\":\"%u.%u.%u.%u\"},\n",	\
								tmp_dns->name,								\
								NIPQUAD(edge->edge_key.faddr));}			\
				}else{														\
					if(tmp_dns == NULL){									\
						non_dns_count++;									\
						fprintf(fp, "{\"name\":\"#%d\","					\
							"\"mac\":\"N/A\",\"ip\":\"N/A\"},\n",			\
							HASH_COUNT(dns_hhead)+non_dns_count);}			\
					else{													\
						fprintf(fp, "{\"name\":\"#%d\","					\
							"\"mac\":\"N/A\",\"ip\":\"N/A\"},\n",			\
							tmp_dns->id);}}									\
				tgt_idx = nxt_idx++;									\
				create_jf_entry(edge->edge_key.faddr, tgt_idx);			\
			}else{														\
				tgt_idx = tmp_jf->node_idx;}							\
			print_val = value;											\
			add_bglink(src_idx, tgt_idx, print_val);					\
			edges_count++;												\
		}else if(value>0){												\
			rest_val += value;											\
			rest_host_count += 1;}}										\
	if(rest_host_count>0){												\
		rest_tgt_idx = nxt_idx++;										\
		add_bglink(rest_src_idx,rest_tgt_idx,rest_val);					\
		fprintf(fp, "{\"name\":\"%d other hosts\","						\
					"\"mac\":\"N/A\",\"ip\":\"N/A\"},\n",				\
					rest_host_count);									\
		rest_host_count = 0;											\
		rest_val = 0;}													\
	fprintf(fp, "{\"name\":\"\",\"mac\":\"\",\"ip\":\"\"}\n], \n");		\
	fprintf(fp, "\"links\":[\n");										\
	while(bglink_count>0){												\
		tmp_bgl = rm_bglink();											\
		fprintf(fp, "{\"source\":%d,\"target\":%d,\"value\":%llu}", 	\
			tmp_bgl.v_src, tmp_bgl.v_tgt, tmp_bgl.v_val);				\
		if(bglink_count > 0){fprintf(fp, ",\n");}						\
		else{fprintf(fp, "\n]}\n");}}									\
	fclose(fp);															\
	clean_jf_hash();													\
	bglink_head = NULL;													\
	bglink_tail= NULL;													\
	bglink_count=0;														\
	nxt_idx = 0;														\
	edges_count = 0;													\
	rest_val = 0;														\
	rest_host_count = 0;												\
}while(0)


int32_t time_diff_msec(struct timeval start, struct timeval end);
int dir_check(char *drohn_dir);

/* Network related functions:
 * update_lan_if(): get LAN IP address and LAN netmask
 * addr_is_local(): return 1 for local address, otherwise 0
 * addr_is_special(): return 1 for broadcast address, otherwise 0
 */
void get_fid_key();
void update_lan_if();
void update_arp();
void update_dhcp_info();
int addr_is_local(__be32 addr);
int addr_is_special(__be32 addr);
uint16_t gen_lid(__be32 addr);

void handle_exp_stat(struct ipflow_exp_stat *exp_stat,
					uint64_t *expired, uint64_t *active);
void handle_exp_entry(__be32 lan_addr, __be32 lan_mask,
					struct ipflow_exp *exp_entry, int is_active);
void handle_dns_entry(struct dns_record_exp *entry);
int init_lhstat(char *drohn_dir);
void init_rf(char *drohn_dir);
void init_arp(char *drohn_dir);
void init_dns(char *drohn_dir);
void backup_lhstat(char *drohn_dir);
void backup_rf(char *drohn_dir);
void backup_arp(char *drohn_dir);
void backup_dns(char *drohn_dir);
void clean_edges_hash();
void clean_cf();
void clean_rf();
void clean_arp();
void clean_dns();
void refresh_table_lhstat();
void update_table_lhstat();
void output_table_lhstat();
void gen_edges();
void export_edges(char *drohn_dir, int has_new_lids);
int encrypt(uint32_t faddr, int padded_faddr_len, 
			unsigned char *key, unsigned char *fid_b64);
void add_bglink(int src, int tgt, uint64_t val);
struct bglink_list rm_bglink();
void gen_top_k_json(char *drohn_dir, int max_edges_num);
void gen_overview_json(char *drohn_dir);
void gen_avg_overview_json(char *drohn_dir);
void gen_timestamp(char *drohn_dir, struct timeval start);

/* Exit with error message */
void die_with_error(const char *msg);

#endif
