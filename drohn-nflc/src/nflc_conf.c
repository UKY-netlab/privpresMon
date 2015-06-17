#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "nflc_conf.h"

extern struct nflc_conf if_conf;

time_t get_mtime(const char *path){
	struct stat statbuf;
	if(stat(path, &statbuf) == -1){
		return 0;
	}
	return statbuf.st_mtime;
}

void get_conf(){
	
#ifdef NFLC_DEBUG
	fprintf(stderr, "%s\n", __FUNCTION__);
#endif
	char name[CONF_STR_SIZE], value[CONF_STR_SIZE];
	time_t d_mtime, n_mtime;

	/* Read DROHN conf */
	d_mtime = get_mtime(DROHN_CONF_FILE);
	printf("%d  %d", if_conf.drohn_mtime, d_mtime);
	FILE *fp = fopen (DROHN_CONF_FILE, "r");
	if(d_mtime > if_conf.drohn_mtime && fp != NULL){
		while(fscanf(fp, " %[^=]=%s", name, value) != EOF){
			if(strncmp("lan_if", name, CONF_STR_SIZE)==0){
				strncpy(if_conf.lan_if, value, sizeof(if_conf.lan_if));
			}
			if(strncmp("wan_if", name, CONF_STR_SIZE)==0){
				strncpy(if_conf.wan_if, value, sizeof(if_conf.wan_if));
			}
		}
		if_conf.drohn_mtime = d_mtime;
		fclose(fp);
	} // End of if(fp != NULL) 

	/* Read NFLC conf */
	n_mtime = get_mtime(NFLC_CONF_FILE);
	fp = fopen (NFLC_CONF_FILE, "r");
	if(n_mtime > if_conf.nflc_mtime && fp != NULL){
		while(fscanf(fp, " %[^=]=%s", name, value) != EOF){
			if(strncmp("resolve_sites", name, CONF_STR_SIZE)==0){
				if(strncmp("1", value, 1) == 0)
					if_conf.resolve_sites = 1;
				else
					if_conf.resolve_sites = 0;
			}
			if(strncmp("use_oui", name, CONF_STR_SIZE)==0){
				if(strncmp("1", value, 1) == 0)
					if_conf.use_oui = 1;
				else
					if_conf.use_oui = 0;
			}
		}
		if_conf.nflc_mtime = n_mtime;
		fclose(fp);
	}
}