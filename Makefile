
SO_VER=2
OBJS=nss-confd-pw.o nss-confd-gr.o nss-confd-sp.o

prefix?=/usr/local
sysconf_dir?=$(prefix)/etc
CFLAGS+=-fPIC -DPASSWD_DIR=\"$(sysconf_dir)/passwd.d\" -DGROUP_DIR=\"$(sysconf_dir)/group.d\"  -DSHADOW_DIR=\"$(sysconf_dir)/shadow.d\"

CFLAGS+=-Wall -g

all: nss-confd

nss-confd: $(OBJS)
	$(CC) -shared -o libnss_confd.so.$(SO_VER) -Wl,-soname,libnss_confd.so.$(SO_VER) $(OBJS) $(LDFLAGS)

clean:
	rm -rf *.o libnss_confd.so.$(SO_VER)
