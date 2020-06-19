/*
 * nss-confd-sp
 * ------------
 * 
 * With nss-confd, entries of certain NSS files like /etc/passwd can be
 * split among multiple files in a certain directory (e.g., /etc/passwd.d/).
 * 
 * This file is responsible for shadow queries.
 * 
 * Written 2020 by Mario Kicherer (dev@kicherer.org)
 * 
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <regex.h>

#include <nss.h>
#include <shadow.h>

#include "nss-confd.h"

static struct table *tables = 0;
static size_t n_tables = 0;
static struct table *cur_table = 0;
static char *cur_pos = 0;

static regex_t sp_regex;


// initialize this module - e.g., open all files
enum nss_status _nss_confd_setspent(void) {
	DIR *dp;
	struct dirent *ep;
	int r;
	char *shadow_dir;
	
	
	if (tables)
		return NSS_STATUS_SUCCESS;
	
	if (getenv("NSS_CONFD_DEBUG")) {
		long long value;
		
		r = parse_llong(getenv("NSS_CONFD_DEBUG"), &value);
		if (r == 0) {
			log_level = value;
		}
	}
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_setspent()\n");
	
	shadow_dir = getenv("NSS_CONFD_SHADOW_DIR");
	
	if (shadow_dir == 0)
		shadow_dir = SHADOW_DIR;
	
	if (log_level >= LL_DBG)
		DBG("open dir \"%s\"\n", shadow_dir);
	
	dp = opendir(shadow_dir);
	if (!dp) {
		if (log_level >= LL_ERROR)
			ERROR("opendir(%s) failed: %s\n", shadow_dir, strerror(errno));
		
		return NSS_STATUS_UNAVAIL;
	}
	
	while (1) {
		ep = readdir(dp);
		if (!ep)
			break;
		
		if (ep->d_type != DT_REG && ep->d_type != DT_LNK)
			continue;
		
		n_tables += 1;
		tables = (struct table *) realloc(tables, sizeof(struct table) * n_tables);
		if (!tables) {
			if (log_level >= LL_ERROR)
				ERROR("realloc(%zu) failed: %s\n", sizeof(struct table) * n_tables, strerror(errno));
			
			return NSS_STATUS_UNAVAIL;
		}
		
		cur_table = &tables[n_tables-1];
		
		asprintf(&cur_table->filepath, "%s/%s", shadow_dir, ep->d_name);
		
		cur_table->fd = open(cur_table->filepath, O_RDONLY);
		
		if (fstat(cur_table->fd, &cur_table->stat) == -1) {
			close(cur_table->fd);
			free(cur_table->filepath);
			
			n_tables -= 1;
			
			continue;
		}
		
		cur_table->data = mmap(0, cur_table->stat.st_size, PROT_READ, MAP_SHARED, cur_table->fd, 0);
		if (cur_table->data == MAP_FAILED) {
			close(cur_table->fd);
			free(cur_table->filepath);
			
			n_tables -= 1;
			
			continue;
		}
	}
	
	closedir(dp);
	
	cur_table = tables;
	if (cur_table)
		cur_pos = cur_table->data;
	
	#define COLUMN "([^:]*)"
	r = regcomp(&sp_regex, "^" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN "$", REG_EXTENDED | REG_NEWLINE);
	if (r) {
		if (log_level >= LL_ERROR)
			ERROR("regcomp sp_regex failed: %s\n", strerror(r));
		
		// TODO should we free $tables or is a caller expected to call _nss_confd_endspent()?
		
		return NSS_STATUS_UNAVAIL;
	} else {
		// although regcomp does not use errno, it might be set afterwards
		// which is permitted by the errno convention
		errno = 0;
	}
	
	return NSS_STATUS_SUCCESS;
}

// shutdown this module
enum nss_status _nss_confd_endspent(void) {
	size_t i;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_endspent()\n");
	
	regfree(&sp_regex);
	
	for (i=0; i < n_tables; i++) {
		cur_table = &tables[i];
		
		munmap(cur_table->data, cur_table->stat.st_size);
		close(cur_table->fd);
		
		free(cur_table->filepath);
	}
	
	if (tables)
		free(tables);
	
	tables = 0;
	n_tables = 0;
	cur_table = 0;
	cur_pos = 0;
	
	return NSS_STATUS_SUCCESS;
}

// this function is called to iterate through all entries
enum nss_status _nss_confd_getspent_r_helper(
	struct spwd *result, char *buffer, size_t buflen, int *errnop,
	struct table **l_cur_table, char **l_cur_pos
)
{
	enum nss_status retval;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_getspent_r()\n");
	
	retval = NSS_STATUS_NOTFOUND;
	
	if (!tables) {
		enum nss_status r;
		
		r = _nss_confd_setspent();
		if (r != NSS_STATUS_SUCCESS) {
			*errnop = ENOENT;
			
			return r;
		}
	}
	
	if (!(*l_cur_table)) {
		*errnop = ENOENT;
		
		return NSS_STATUS_NOTFOUND;
	}
	
	while (1) {
		int r;
		char errbuf[128];
		#define N_GROUPS 10
		regmatch_t rmatch[N_GROUPS];
		size_t slen;
		char *bufpos;
		size_t bufidx;
		
		
		if ((*l_cur_table) >= tables + n_tables) {
			*errnop = ENOENT;
			
			return NSS_STATUS_NOTFOUND;
		}
		
		bufpos = buffer;
		bufidx = 0;
		
		r = regexec(&sp_regex, (*l_cur_pos), N_GROUPS, rmatch, 0);
		if (!r) {
			int i, valid;
			
			valid = 1;
			
			if (log_level >= LL_DBG)
				DBG("%s: |", (*l_cur_table)->filepath);
			
			for (i=1; i < N_GROUPS; i++) {
				if (rmatch[i].rm_so == (size_t)-1) {
					// TODO can this still happen?
					
					valid = 0;
					
					break;
				}
				
				slen = rmatch[i].rm_eo - rmatch[i].rm_so;
				
				if (bufidx + slen + 1 >= buflen) {
					*errnop = ERANGE;
					
					return NSS_STATUS_TRYAGAIN;
				}
				
				memcpy(bufpos, &(*l_cur_pos)[rmatch[i].rm_so], slen);
				bufpos[slen] = 0;
				
				if (log_level >= LL_DBG)
					DBG("%s|", bufpos);
				
				switch (i) {
					case 1: result->sp_namp = bufpos; break;
					case 2: result->sp_pwdp = bufpos; break;
					
					SWITCH_ENTRY(3, sp_lstchg)
					SWITCH_ENTRY(4, sp_min)
					SWITCH_ENTRY(5, sp_max)
					SWITCH_ENTRY(6, sp_warn)
					SWITCH_ENTRY(7, sp_inact)
					SWITCH_ENTRY(8, sp_expire)
					SWITCH_ENTRY(9, sp_flag)
				}
				
				bufpos += slen + 1;
				bufidx += slen + 1;
			}
			
			if (log_level >= LL_DBG)
				DBG("\n");
			
			(*l_cur_pos) += rmatch[N_GROUPS-1].rm_eo + 1;
			
			if ((*l_cur_pos) >= (*l_cur_table)->data + (*l_cur_table)->stat.st_size) {
				if (log_level >= LL_DBG)
					DBG("EOF\n");
				
				(*l_cur_table) += 1;
				if ((*l_cur_table) < tables + n_tables)
					(*l_cur_pos) = (*l_cur_table)->data;
			}
			
			if (valid) {
				retval = NSS_STATUS_SUCCESS;
			} else {
				if (log_level >= LL_ERROR)
					DBG("ignoring invalid entry\n");
				continue;
			}
		} else
		if (r == REG_NOMATCH) {
			if (log_level >= LL_DBG)
				DBG("EOF\n");
			
			(*l_cur_table) += 1;
			if ((*l_cur_table) < tables + n_tables)
				(*l_cur_pos) = (*l_cur_table)->data;
			
			continue;
		} else {
			regerror(r, &sp_regex, errbuf, sizeof(errbuf));
			
			if (log_level >= LL_ERROR)
				ERROR("regexec failed: %s\n", errbuf);
			
			*errnop = ENOENT;
			return NSS_STATUS_UNAVAIL;
		}
		
		break;
	}
	
	if (retval == NSS_STATUS_NOTFOUND)
		*errnop = ENOENT;
	
	return retval;
}

// this function is called to iterate through all entries
enum nss_status _nss_confd_getspent_r(struct spwd *result, char *buffer, size_t buflen, int *errnop) {
	return _nss_confd_getspent_r_helper(result, buffer, buflen, errnop, &cur_table, &cur_pos);
}

enum nss_status _nss_confd_getspnam_r(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	struct table *cur_table;
	char *cur_pos;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_getspnam_r()\n");
	
	retval = _nss_confd_setspent();
	if (retval != NSS_STATUS_SUCCESS) {
		*errnop = ENOENT;
		
		return retval;
	}
	
	cur_table = tables;
	cur_pos = cur_table->data;
	
	while (1) {
		retval = _nss_confd_getspent_r_helper(result, buffer, buflen, errnop, &cur_table, &cur_pos);
		
		if (retval != NSS_STATUS_SUCCESS)
			return retval;
		if (!strcmp(result->sp_namp, name))
			return NSS_STATUS_SUCCESS;
	}
}
