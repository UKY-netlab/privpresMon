#ifndef NFLC_CONF_H
#define NFLC_CONF_H

#include <sys/types.h>
#include "nflc.h"

#define DROHN_CONF_FILE "/etc/drohn/drohn.conf"
#define NFLC_CONF_FILE "/etc/nflc/nflc.conf"
#define CONF_STR_SIZE 32
#define CONF_ITEM_CNT 2 
#define DELIM "="

struct nflc_conf
{
	time_t drohn_mtime;
	time_t nflc_mtime;
	char lan_if[CONF_STR_SIZE];
	char wan_if[CONF_STR_SIZE];
	int resolve_sites;
	int use_oui;
};

void get_conf();

#endif