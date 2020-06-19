/*
 * nss-confd-gr
 * ------------
 * 
 * With nss-confd, entries of certain NSS files like /etc/passwd can be
 * split among multiple files in a certain directory (e.g., /etc/passwd.d/).
 * 
 * This file is responsible for group queries.
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
#include <grp.h>

#define LL_NONE 0
#define LL_ERROR 1
#define LL_DBG 2

static int log_level = LL_NONE;

struct table {
	char *filepath;
	struct stat stat;
	int fd;
	char *data;
};

static struct table *tables = 0;
static size_t n_tables = 0;
static struct table *cur_table = 0;
static char *cur_pos = 0;

static regex_t gr_regex;

// in nss-confd-pw.c
extern int parse_llong(char *arg, long long *value);

// initialize this module - e.g., open all files
enum nss_status _nss_confd_setgrent(void) {
	DIR *dp;
	struct dirent *ep;
	int r;
	char *group_dir;
	
	if (getenv("NSS_CONFD_DEBUG")) {
		long long value;
		
		r = parse_llong(getenv("NSS_CONFD_DEBUG"), &value);
		if (r == 0) {
			log_level = value;
		}
	}
	
	if (log_level >= LL_DBG)
		printf("_nss_confd_setgrent()\n");
	
	group_dir = getenv("NSS_CONFD_GROUP_DIR");
	
	if (group_dir == 0)
		group_dir = GROUP_DIR;
	
	if (log_level >= LL_DBG)
		printf("open dir \"%s\"\n", group_dir);
	
	dp = opendir(group_dir);
	if (!dp) {
		if (log_level >= LL_ERROR)
			fprintf(stderr, "opendir(%s) failed: %s\n", group_dir, strerror(errno));
		
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
				fprintf(stderr, "realloc(%zu) failed: %s\n", sizeof(struct table) * n_tables, strerror(errno));
			
			return NSS_STATUS_UNAVAIL;
		}
		
		cur_table = &tables[n_tables-1];
		
		asprintf(&cur_table->filepath, "%s/%s", group_dir, ep->d_name);
		
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
	r = regcomp(&gr_regex, "^" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN "$", REG_EXTENDED | REG_NEWLINE);
	if (r) {
		if (log_level >= LL_ERROR)
			fprintf(stderr, "regcomp gr_regex failed: %s\n", strerror(r));
		
		// TODO should we free $tables or is a caller expected to call _nss_confd_endgrent()?
		
		return NSS_STATUS_UNAVAIL;
	}
	
	return NSS_STATUS_SUCCESS;
}

// shutdown this module
enum nss_status _nss_confd_endgrent(void) {
	size_t i;
	
	if (log_level >= LL_DBG)
		printf("_nss_confd_endgrent()\n");
	
	regfree(&gr_regex);
	
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
enum nss_status _nss_confd_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	
	if (log_level >= LL_DBG)
		printf("_nss_confd_getgrent_r()\n");
	
	retval = NSS_STATUS_NOTFOUND;
	
	if (!tables) {
		enum nss_status r;
		
		r = _nss_confd_setgrent();
		if (r != NSS_STATUS_SUCCESS) {
			*errnop = ENOENT;
			
			return r;
		}
	}
	
	if (!cur_table) {
		*errnop = ENOENT;
		
		return NSS_STATUS_NOTFOUND;
	}
	
	while (1) {
		int r;
		char errbuf[128];
		#define N_GROUPS 5
		regmatch_t rmatch[N_GROUPS];
		size_t slen;
		char *bufpos;
		size_t bufidx;
		
		
		if (cur_table >= tables + n_tables) {
			*errnop = ENOENT;
			
			return NSS_STATUS_NOTFOUND;
		}
		
		bufpos = buffer;
		bufidx = 0;
		
		r = regexec(&gr_regex, cur_pos, N_GROUPS, rmatch, 0);
		if (!r) {
			int i, valid;
			
			valid = 1;
			
			if (log_level >= LL_DBG)
				printf("%s: |", cur_table->filepath);
			
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
				
				memcpy(bufpos, &cur_pos[rmatch[i].rm_so], slen);
				bufpos[slen] = 0;
				
				if (log_level >= LL_DBG)
					printf("%s|", bufpos);
				
				switch (i) {
					case 1: result->gr_name = bufpos; break;
					case 2: result->gr_passwd = bufpos; break;
					case 3: {
						int r;
						long long value;
						
						r = parse_llong(bufpos, &value);
						if (r == 0) {
							result->gr_gid = value;
						} else {
							valid = 0;
						}
						
						break;
					}
					case 4: {
// 						result->gr_mem = bufpos; break;
						
						size_t j, k, member_count, last_valid;
						
						member_count = 0;
						for (j=0; j < slen; j ++) {
							if (bufpos[j] == ',') {
								member_count += 1;
								if (j < slen)
									last_valid = 1;
								else
									last_valid = 0;
							}
						}
						if (last_valid)
							member_count += 1;
						
						result->gr_mem = (char **) bufpos + slen + 1;
						
						if (member_count > 0) {
							result->gr_mem[0] = bufpos;
							k = 1;
							for (j=0; j < slen; j ++) {
								if (bufpos[j] == ',') {
									result->gr_mem[k] = &bufpos[j+1];
									bufpos[j] = 0;
									k += 1;
								}
							}
							result->gr_mem[k] = 0;
						} else {
							result->gr_mem[0] = 0;
						}
						
						member_count += 1;
						bufpos += member_count * sizeof(char*);
						bufidx += member_count * sizeof(char*);
						
						break;
					}
				}
				
				bufpos += slen + 1;
				bufidx += slen + 1;
			}
			
			if (log_level >= LL_DBG)
				printf("\n");
			
			cur_pos += rmatch[N_GROUPS-1].rm_eo + 1;
			
			if (cur_pos >= cur_table->data + cur_table->stat.st_size) {
				if (log_level >= LL_DBG)
					printf("EOF\n");
				
				cur_table += 1;
				if (cur_table < tables + n_tables)
					cur_pos = cur_table->data;
			}
			
			if (valid) {
				retval = NSS_STATUS_SUCCESS;
			} else {
				if (log_level >= LL_ERROR)
					fprintf(stderr, "ignoring invalid entry\n");
				continue;
			}
		} else
		if (r == REG_NOMATCH) {
			if (log_level >= LL_DBG)
				printf("EOF\n");
			
			cur_table += 1;
			if (cur_table < tables + n_tables)
				cur_pos = cur_table->data;
			
			continue;
		} else {
			regerror(r, &gr_regex, errbuf, sizeof(errbuf));
			
			if (log_level >= LL_ERROR)
				fprintf(stderr, "regexec failed: %s\n", errbuf);
			
			*errnop = ENOENT;
			return NSS_STATUS_UNAVAIL;
		}
		
		break;
	}
	
	if (retval == NSS_STATUS_NOTFOUND)
		*errnop = ENOENT;
	
	return retval;
}

enum nss_status _nss_confd_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	
	if (log_level >= LL_DBG)
		printf("_nss_confd_getgruid_r()\n");
	
	while (1) {
		retval = _nss_confd_getgrent_r(result, buffer, buflen, errnop);
		if (retval != NSS_STATUS_SUCCESS)
			return retval;
		
		if (result->gr_gid == gid)
			return NSS_STATUS_SUCCESS;
	}
}

enum nss_status _nss_confd_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	
	if (log_level >= LL_DBG)
		printf("_nss_confd_getgrnam_r()\n");
	
	while (1) {
		retval = _nss_confd_getgrent_r(result, buffer, buflen, errnop);
		if (retval != NSS_STATUS_SUCCESS)
			return retval;
		
		if (!strcmp(result->gr_name, name))
			return NSS_STATUS_SUCCESS;
	}
}
