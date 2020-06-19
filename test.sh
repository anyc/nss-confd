#! /bin/bash

[ -e libnss_confd.so.2 ] || { echo "libnss_confd.so.2 not found"; exit 1; }

function getent_call() {
#	VALGRIND="valgrind --leak-check=full"

	NSS_CONFD_DEBUG=1 \
		NSS_CONFD_PASSWD_DIR=$(pwd)/tests/passwd.d/ \
		NSS_CONFD_GROUP_DIR=$(pwd)/tests/group.d/ \
		NSS_CONFD_SHADOW_DIR=$(pwd)/tests/shadow.d/ \
		LD_LIBRARY_PATH=$(pwd) \
		${VALGRIND} getent $*
	RES="$?"

	if [ "${RES}" != "0" ]; then
		echo "ERROR getent_call $*" >&2
		exit 1
	fi
}

function getent_test() {
	RES=$(getent_call ${1} ${2})

	if [ "${RES}" != "${3}" ]; then
		echo "error ${1} ${2} got: \"${RES}\" expected \"${3}\""
		exit 1
	fi
}

getent_test passwd f1 "f1:f2:3:4:f5:f6:f7"
getent_test passwd g1 "g1:g2:5:6:g5:g6:g7"
getent_test passwd h1 "h1:h2:3:4:h5:h6:h7"
getent_test passwd j1 "j1:j2:3:4:::"

getent_test passwd x1 ""
getent_test passwd y1 ""
getent_test passwd z1 ""

getent_test group a1 "a1:a2:1:"
getent_test group b1 "b1:b2:2:user1"
getent_test group c1 "c1:c2:3:user1,user2"
getent_test group d1 "d1:d2:4:user1,user2,"
getent_test group e1 "e1:e2:5:user1,user2,user3"

getent_test group x1 ""

getent_test shadow a1 "a1:a2:10:11:12:13:14:15:16"
getent_test shadow b1 "b1:b2:20:21:22:23:24:25:26"
getent_test shadow c1 "c1:c2:30:31:32:33:34:35:36"
getent_test shadow d1 ""

getent_test shadow x1 ""

echo success
exit 0
