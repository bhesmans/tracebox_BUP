Tracebox
========

Tracebox is a tool that allows to identify the middleboxes between you and a
destination.

Compiling
---------

Tracebox requires to have installed:

* Development package of libpcap
* automake, autoconf and libtool

To build:

	$ ./bootstrap.sh
	$ make
	$ sudo make install # optional

Usage
-----
	  ./tracebox [ -6thnb ] [ -i device ] [ -m hops_max ] [ -o option ] host
	Options:
	  -h                          Display this help and exit
	  -n                          Do not resolve IP adresses
	  -i device                   Specify a network interface to operate with
	  -m hops_max                 Set the max number of hops (max TTL to be
	                              reached). Default is 30
	  -o option                   Define the TCP option to put in the SYN segment.
	                              Default is none. -o list for a list of available
	                              options.