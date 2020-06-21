
#define LL_NONE 0
#define LL_ERROR 1
#define LL_DBG 2

#define DBG(fmt, ...) do { if (log_level >= LL_DBG) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define ERROR(fmt, ...) do { if (log_level >= LL_ERROR) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

extern int log_level;

// in nss-confd-pw.c
extern int parse_llong(char *arg, long long *value);

struct table {
	char *filepath;
	struct stat stat;
	int fd;
	char *data;
};

#define SWITCH_ENTRY(i, entry) \
	case i: { \
		int r; \
		long long value; \
		\
		if (slen > 0) { \
			r = parse_llong(bufpos, &value); \
			if (r == 0) { \
				result->entry = value; \
			} else { \
				valid = 0; \
			} \
		} else { \
			result->entry = -1; \
		} \
		\
		break;\
	}
