nss-confd
=========

nss-confd is a module for the Name Service Switch (NSS) of glibc. With nss-confd,
entries of certain NSS file services like /etc/passwd can be split among multiple
files in a certain directory (e.g., /etc/passwd.d/).

For example, users or groups for a certain service can be added or removed by
creating or deleting an individual file. These files can be part of the package
of this service and the directory containing these files can be in an arbitrary
location or mount namespace, for example.

Status
------

Currently, the following NSS services are supported:

 * passwd
 * shadow
 * group

Usage
-----

 1. Build the project: `make && make install`
 2. Create new entries in `/etc/passwd.d`, `/etc/shadow.d` or `/etc/group.d`

The path of the directories can also be changed dynamically using the following
environment variables:

 * NSS_CONFD_PASSWD_DIR
 * NSS_CONFD_SHADOW_DIR
 * NSS_CONFD_GROUP_DIR
