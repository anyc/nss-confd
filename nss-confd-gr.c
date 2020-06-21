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

#include "nss-confd.h"

static struct table *tables = 0;
static size_t n_tables = 0;
static struct table *cur_table = 0;
static char *cur_pos = 0;

static regex_t gr_regex;

#ifdef NSS_CONFD_WITH_SPLIT_MEMBERS
static struct table *split_members = 0;
static size_t n_split_members = 0;

static regex_t gm_regex;
#endif

// initialize this module - e.g., open all files
enum nss_status _nss_confd_setgrent(void) {
	struct dirent *ep;
	int i, r, n_entries, abort;
	char *dirpath;
	struct dirent **namelist;
	
	
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
		DBG("_nss_confd_setgrent()\n");
	
	dirpath = getenv("NSS_CONFD_GROUP_DIR");
	
	if (dirpath == 0)
		dirpath = GROUP_DIR;
	
	if (log_level >= LL_DBG)
		DBG("open dir \"%s\"\n", dirpath);
	
	n_entries = scandir(dirpath, &namelist, 0, alphasort);
	if (n_entries < 0) {
		if (log_level >= LL_ERROR)
			ERROR("scandir(%s) failed: %s\n", dirpath, strerror(errno));
		
		return NSS_STATUS_UNAVAIL;
	}
	
	abort = 0;
	for (i = 0; i < n_entries; i++) {
		ep = namelist[i];
		
		if (ep->d_type != DT_REG)
			continue;
		
		#ifdef NSS_CONFD_WITH_SPLIT_MEMBERS
		size_t slen;
		
		slen = strlen(ep->d_name);
		
		if (slen > 11) {
			if (!strcmp(&ep->d_name[slen - 11], ".membership")) {
				n_split_members += 1;
				split_members = (struct table *) realloc(split_members, sizeof(struct table) * n_split_members);
				if (!split_members) {
					if (log_level >= LL_ERROR)
						ERROR("realloc(%zu) failed: %s\n", sizeof(struct table) * n_split_members, strerror(errno));
					
					abort = 1;
					break;
				}
				
				cur_table = &split_members[n_split_members-1];
				
				asprintf(&cur_table->filepath, "%s/%s", dirpath, ep->d_name);
				
				cur_table->fd = open(cur_table->filepath, O_RDONLY);
				
				if (fstat(cur_table->fd, &cur_table->stat) == -1) {
					close(cur_table->fd);
					free(cur_table->filepath);
					
					n_split_members -= 1;
					
					continue;
				}
				
				cur_table->data = mmap(0, cur_table->stat.st_size, PROT_READ, MAP_SHARED, cur_table->fd, 0);
				if (cur_table->data == MAP_FAILED) {
					close(cur_table->fd);
					free(cur_table->filepath);
					
					n_split_members -= 1;
					
					continue;
				}
				
				continue;
			}
		}
		#endif
		
		n_tables += 1;
		tables = (struct table *) realloc(tables, sizeof(struct table) * n_tables);
		if (!tables) {
			if (log_level >= LL_ERROR)
				ERROR("realloc(%zu) failed: %s\n", sizeof(struct table) * n_tables, strerror(errno));
			
			abort = 1;
			break;
		}
		
		cur_table = &tables[n_tables-1];
		
		asprintf(&cur_table->filepath, "%s/%s", dirpath, ep->d_name);
		
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
	
	for (i = 0; i < n_entries; i++) {
		free(namelist[i]);
	}
	free(namelist);
	
	if (abort)
		return NSS_STATUS_UNAVAIL;
	
	cur_table = tables;
	if (cur_table)
		cur_pos = cur_table->data;
	
	#define COLUMN "([^:]*)"
	r = regcomp(&gr_regex, "^" COLUMN ":" COLUMN ":" COLUMN ":" COLUMN "$", REG_EXTENDED | REG_NEWLINE);
	if (r) {
		if (log_level >= LL_ERROR)
			ERROR("regcomp gr_regex failed: %s\n", strerror(r));
		
		// TODO should we free $tables or is a caller expected to call _nss_confd_endgrent()?
		
		return NSS_STATUS_UNAVAIL;
	} else {
		// although regcomp does not use errno, it might be set afterwards
		// which is permitted by the errno convention
		errno = 0;
	}
	
	#ifdef NSS_CONFD_WITH_SPLIT_MEMBERS
	r = regcomp(&gm_regex, "^" COLUMN ":" COLUMN "$", REG_EXTENDED | REG_NEWLINE);
	if (r) {
		if (log_level >= LL_ERROR)
			ERROR("regcomp gr_regex failed: %s\n", strerror(r));
		
		// TODO should we free $tables or is a caller expected to call _nss_confd_endgrent()?
		
		return NSS_STATUS_UNAVAIL;
	} else {
		// although regcomp does not use errno, it might be set afterwards
		// which is permitted by the errno convention
		errno = 0;
	}
	#endif
	
	return NSS_STATUS_SUCCESS;
}

// shutdown this module
enum nss_status _nss_confd_endgrent(void) {
	size_t i;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_endgrent()\n");
	
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

#ifdef NSS_CONFD_WITH_SPLIT_MEMBERS
// this function parses the split_members files and appends the members of the given group to the buffer
int find_members(char *gr_name, char *buffer, char *bufpos, size_t buflen, size_t *new_slen) {
	struct table *cur_sm_table;
	char *cur_sm_pos;
	
	
	*new_slen = 0;
	
	cur_sm_table = split_members;
	if (split_members)
		cur_sm_pos = split_members->data;
	else
		return 0;
	
	while (1) {
		int r;
		char errbuf[128];
		#define N_MEMBERS_GROUPS 3
		regmatch_t rmatch[N_MEMBERS_GROUPS];
		size_t slen;
		
		
		if (cur_sm_table >= split_members + n_split_members) {
			break;
		}
		
		r = regexec(&gm_regex, cur_sm_pos, N_MEMBERS_GROUPS, rmatch, 0);
		if (!r) {
			int i, skip;
			
			skip = 1;
			
			if (log_level >= LL_DBG)
				DBG("%s: |", cur_sm_table->filepath);
			
			for (i=1; i < N_MEMBERS_GROUPS; i++) {
				if (rmatch[i].rm_so == (size_t)-1) {
					// TODO can this still happen?
					
					break;
				}
				
				slen = rmatch[i].rm_eo - rmatch[i].rm_so;
				
				if ((bufpos - buffer) + slen + 1 >= buflen) {
					return NSS_STATUS_TRYAGAIN;
				}
				
				memcpy(bufpos, &cur_sm_pos[rmatch[i].rm_so], slen);
				bufpos[slen] = 0;
				
				if (log_level >= LL_DBG)
					DBG("%s|", bufpos);
				
				switch (i) {
					case 1:
						if (!strcmp(gr_name, bufpos))
							skip = 0;
						
						break;
					case 2: {
						// add additional ',', the calling function will remove the last one later
						bufpos[slen] = ',';
						bufpos[slen+1] = 0;
						bufpos += slen + 1;
						*new_slen += slen + 1;
					}
				}
				
				if (skip)
					break;
			}
			
			if (log_level >= LL_DBG)
				DBG("\n");
			
			cur_sm_pos += rmatch[N_MEMBERS_GROUPS-1].rm_eo + 1;
			
			if (cur_sm_pos >= cur_sm_table->data + cur_sm_table->stat.st_size) {
				if (log_level >= LL_DBG)
					DBG("EOF\n");
				
				cur_sm_table += 1;
				if (cur_sm_table < split_members + n_split_members)
					cur_sm_pos = cur_sm_table->data;
			}
		} else
		if (r == REG_NOMATCH) {
			if (log_level >= LL_DBG)
				DBG("EOF\n");
			
			cur_sm_table += 1;
			if (cur_sm_table < split_members + n_split_members)
				cur_sm_pos = cur_sm_table->data;
		} else {
			regerror(r, &gr_regex, errbuf, sizeof(errbuf));
			
			if (log_level >= LL_ERROR)
				ERROR("regexec failed: %s\n", errbuf);
			
			return -1;
		}
	}
	
	return 0;
}
#endif

// this function is called to iterate through all entries
enum nss_status _nss_confd_getgrent_r_helper(
	struct group *result, char *buffer, size_t buflen, int *errnop,
	struct table **l_cur_table, char **l_cur_pos
	)
{
	enum nss_status retval;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_getgrent_r()\n");
	
	retval = NSS_STATUS_NOTFOUND;
	
	if (!tables) {
		enum nss_status r;
		
		r = _nss_confd_setgrent();
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
		#define N_GROUPS 5
		regmatch_t rmatch[N_GROUPS];
		size_t slen;
		char *bufpos;
		
		
		if ((*l_cur_table) >= tables + n_tables) {
			*errnop = ENOENT;
			
			return NSS_STATUS_NOTFOUND;
		}
		
		bufpos = buffer;
		
		r = regexec(&gr_regex, (*l_cur_pos), N_GROUPS, rmatch, 0);
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
				
				if ((bufpos - buffer) + slen + 1 >= buflen) {
					*errnop = ERANGE;
					
					return NSS_STATUS_TRYAGAIN;
				}
				
				memcpy(bufpos, &(*l_cur_pos)[rmatch[i].rm_so], slen);
				bufpos[slen] = 0;
				
				if (log_level >= LL_DBG)
					DBG("%s|", bufpos);
				
				switch (i) {
					case 1: result->gr_name = bufpos; break;
					case 2: result->gr_passwd = bufpos; break;
					
					SWITCH_ENTRY(3, gr_gid)
					
					case 4: {
						size_t j, k, member_count, last_valid;
						
						/*
						 * the member list is already stored in the buffer, we just
						 * have to replace the "," with zeroes to generate valid strings
						 * and to store pointers into the string list
						 */
						
						#ifdef NSS_CONFD_WITH_SPLIT_MEMBERS
						size_t new_slen;
						char *start_pos;
						
						start_pos = bufpos + slen;
						// if there is already a member, leave space for a ','
						if (slen > 0)
							start_pos += 1;
						
						// get the list of additional members and append it to the member list in $buffer
						r = find_members(result->gr_name, buffer, start_pos, buflen, &new_slen);
						if (r == 0) {
							if (new_slen > 0) {
								// replace null termination with ','
								if (slen > 0)
									bufpos[slen] = ',';
								
								// set new null terminator
								start_pos[new_slen -1] = 0;
								
								slen += new_slen;
							}
						} else {
							if (r == NSS_STATUS_TRYAGAIN) {
								*errnop = ERANGE;
								
								return NSS_STATUS_TRYAGAIN;
							}
						}
						#endif
						
						// get the number of ',' = number of members - 1
						last_valid = ( slen > 0 );
						member_count = 0;
						for (j=0; j < slen; j++) {
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
						
						// "allocate" the string list
						result->gr_mem = (char **) (bufpos + slen + 1);
						
						// fill the string list with pointers and replace ',' with 0
						k = 0;
						if (member_count > 0) {
							result->gr_mem[k] = bufpos;
							k += 1;
							
							for (j=0; j < slen; j++) {
								if (bufpos[j] == ',') {
									result->gr_mem[k] = &bufpos[j+1];
									k += 1;
									
									bufpos[j] = 0;
								}
							}
						}
						
						result->gr_mem[k] = 0;
						member_count += 1;
						
						bufpos += member_count * sizeof(char*);
						
						break;
					}
				}
				
				bufpos += slen + 1;
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
					ERROR("ignoring invalid entry\n");
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
			regerror(r, &gr_regex, errbuf, sizeof(errbuf));
			
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
enum nss_status _nss_confd_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop) {
	return _nss_confd_getgrent_r_helper(result, buffer, buflen, errnop, &cur_table, &cur_pos);
}

enum nss_status _nss_confd_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	struct table *cur_table;
	char *cur_pos;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_getgruid_r()\n");
	
	retval = _nss_confd_setgrent();
	if (retval != NSS_STATUS_SUCCESS) {
		*errnop = ENOENT;
		
		return retval;
	}
	
	cur_table = tables;
	if (tables) {
		cur_pos = cur_table->data;
	} else {
		*errnop = ENOENT;
		
		return NSS_STATUS_NOTFOUND;
	}
	
	while (1) {
		retval = _nss_confd_getgrent_r_helper(result, buffer, buflen, errnop, &cur_table, &cur_pos);
		if (retval != NSS_STATUS_SUCCESS)
			return retval;
		
		if (result->gr_gid == gid)
			return NSS_STATUS_SUCCESS;
	}
}

enum nss_status _nss_confd_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop) {
	enum nss_status retval;
	struct table *cur_table;
	char *cur_pos;
	
	if (log_level >= LL_DBG)
		DBG("_nss_confd_getgrnam_r()\n");
	
	retval = _nss_confd_setgrent();
	if (retval != NSS_STATUS_SUCCESS) {
		*errnop = ENOENT;
		
		return retval;
	}
	
	cur_table = tables;
	if (tables) {
		cur_pos = cur_table->data;
	} else {
		*errnop = ENOENT;
		
		return NSS_STATUS_NOTFOUND;
	}
	
	while (1) {
		retval = _nss_confd_getgrent_r_helper(result, buffer, buflen, errnop, &cur_table, &cur_pos);
		if (retval != NSS_STATUS_SUCCESS)
			return retval;
		
		if (!strcmp(result->gr_name, name))
			return NSS_STATUS_SUCCESS;
	}
}
