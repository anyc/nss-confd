
SO_VER=2
OBJS=nss-confd-pw.o

CFLAGS+=-fPIC -DPASSWD_DIR=\"/etc/passwd.d\"

CFLAGS+=-Wall -g

all: nss-confd

nss-confd: $(OBJS)
	$(CC) -shared -o libnss_confd.so.$(SO_VER) -Wl,-soname,libnss_confd.so.$(SO_VER) $(OBJS) $(LDFLAGS)

clean:
	rm -rf *.o libnss_confd.so.$(SO_VER)
