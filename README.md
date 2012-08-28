ARMT
====

ARMT (Another Remote Monitoring Tool) is another tool to assist server
administrators in their fight to keep servers online.

This tool is still a work in progress so do not expect too much yet.

Currently monitoring of a remote server is performed via various scripts many of
which perform simple repeatble tasks, such as checking for a running process or
checking if a service such as HTTP is alive.

Other checks are not feasable or are a pain to perform as they require support
of other tools such as a recent version of smartmontools, or other dependent
libraries that may not be installed on the target machine.

ARMT aims to work around these issues by compiling to a static binary that
contains all the required support tools embedded also as static binaries. So far
ARMT is able to perform the following:

* Get installed PCI devices
* Get SMART status of block devices
* Get CCISS RAID status of arrays
* Get MD (Software) RAID status of arrays
* Get a running process list and ports bound to processes
* Connect to a HTTP(s) server
* Create and compare a MD5 hash database of critical system files

To perform these tasks ARMT uses the following support libraries and executables

* libpcre
* polarssl
* smartctl
* cciss\_vol\_status
* megactl (not used yet)
* lsscsi  (not used yet and may be removed)
* zlib (not used yet)

To avoid shared linking ARMT also has it's own built-in DNS resolver that wraps
gethostbyname as linking to `gethostbyname` causes a system dependency on the
shared libc. 
