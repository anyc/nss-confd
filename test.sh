#! /bin/bash

[ -e libnss_confd.so.2 ] || { echo "libnss_confd.so.2 not found"; exit 1; }

function getent_call() {
#	VALGRIND="valgrind --leak-check=full"

	NSS_CONFD_PASSWD_DIR=$(pwd)/tests/passwd.d/ NSS_CONFD_DEBUG=1 LD_LIBRARY_PATH=$(pwd) ${VALGRIND} getent passwd $*
	RES="$?"

	if [ "${RES}" != "0" ]; then
		echo "ERROR getent_call $*" >&2
		exit 1
	fi
}

function getent_test() {
	RES=$(getent_call ${1})

	if [ "${RES}" != "${2}" ]; then
		echo "error ${1} got: \"${RES}\" expected \"${2}\""
		exit 1
	fi
}

getent_test f1 "f1:f2:3:4:f5:f6:f7"
getent_test g1 "g1:g2:5:6:g5:g6:g7"
getent_test h1 "h1:h2:3:4:h5:h6:h7"
getent_test j1 "j1:j2:3:4:::"

getent_test x1 ""
getent_test y1 ""
getent_test z1 ""

echo success
exit 0
