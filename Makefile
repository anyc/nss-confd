
SO_VER=2
OBJS=nss-confd-pw.o nss-confd-gr.o nss-confd-sp.o

prefix?=/
sysconf_dir?=$(prefix)/etc
libdir?=$(prefix)/lib
CFLAGS+=-fPIC -DPASSWD_DIR=\"$(sysconf_dir)/passwd.d\" -DGROUP_DIR=\"$(sysconf_dir)/group.d\"  -DSHADOW_DIR=\"$(sysconf_dir)/shadow.d\"

CFLAGS+=-Wall -g

ifeq ($(WITH_SPLIT_MEMBERS),1)
CFLAGS+=-DNSS_CONFD_WITH_SPLIT_MEMBERS=1
endif

INSTALL?=install

all: libnss_confd.so.$(SO_VER)

libnss_confd.so.$(SO_VER): $(OBJS)
	$(CC) -shared -o $@ -Wl,-soname,$@ $(OBJS) $(LDFLAGS)

install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(sysconf_dir)/passwd.d
	$(INSTALL) -m 755 -d $(DESTDIR)$(sysconf_dir)/group.d
	$(INSTALL) -m 755 -d $(DESTDIR)$(sysconf_dir)/shadow.d
	
	$(INSTALL) -m 755 -d $(DESTDIR)$(libdir)
	
	$(INSTALL) -m 755 libnss_confd.so.$(SO_VER) $(DESTDIR)$(libdir)

clean:
	rm -rf *.o libnss_confd.so.$(SO_VER)
