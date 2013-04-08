#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

def length(res):
    for ttl, r in res.iteritems():
        if r and r.is_srv_reply():
            return ttl
    return None

def length2(res):
    last_r = 1
    for ttl, r in res.iteritems():
        if r and r.is_srv_reply():
            return ttl
        if r:
            last_r = ttl
    return last_r


tcp_ttl = length(do_tracebox(probe))
if not tcp_ttl:
    print "The server did not replied to the probe: we are unable to detect any proxy."

# generate a UDP probe and look if the last reply is farther than TCP
probe2 = IP(dst=dest, proto="udp") / \
        UDP(sport=random.randint(0, 2**16-1),
            dport=53).build()
udp_ttl = length2(do_tracebox(probe2))

if udp_ttl > tcp_ttl:
    print "There is a proxy between you and the destination."