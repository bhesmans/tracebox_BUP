Tracebox
========

Tracebox is a tool that allows to identify the middleboxes between you and a
destination.

Compiling
---------

Tracebox requires to have installed:

* Development package of libpcap and libdnet
* automake, autoconf and libtool

To build:

	$ ./bootstrap.sh
	$ make
	$ sudo make install # optional

Usage
-----
	  ./tracebox [ -hn ] [ -i device ] [ -m hops_max ] [ -o option ] [ -O file ] [ -p port ] [ -f flags ] host
	Options:
	  -h                          Display this help and exit
	  -n                          Do not resolve IP adresses
	  -i device                   Specify a network interface to operate with
	  -m hops_max                 Set the max number of hops (max TTL to be
	                              reached). Default is 30
	  -o option                   Define the TCP option to put in the SYN segment.
	                              Default is none. -o list for a list of available
	                              options.
	  -O file                     Use file to dump the sent and received packets
	  -p port                     Specify the destination port to use when
	                              generating probes. Default is 80.
	  -f flag1[,flag2[,flag3...]] Specify the TCP flags to use. Values are: syn,
	                              ack, fin, rst, push, urg, ece, cwr. Default is:
	                              syn.

Output example:

	$ sudo ./tracebox -n -m 8 -o ts -i en0 87.98.252.243
	tracebox to 87.98.252.243 (): 8 hops max
	 1 130.104.228.126 [DSCP changed] [TCP seq changed] 
	 2 130.104.254.229 
	 3 193.191.3.85 
	 4 194.53.172.70 
	 5 213.251.130.61 [Reply ICMP full pkt] 
	 6 94.23.122.160 
	 7 87.98.252.243 
