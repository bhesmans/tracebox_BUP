#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe = IP(dst=dest, proto="tcp", id=random.randint(0, 2**16-1)) / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

last_res = None
changed = False
for ttl, res in do_tracebox(probe):
    if not res:
        continue
    if res.ip_id_changed() and not last_res.is_srv_reply():
        print "The IP Identification field changed between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
        changed = True
    if res:
        last_res = res

if last_res and last_res.is_srv_reply() and not changed:
    print "The IP Identification field was not modified between you and the destination (%s)." % (last_res.router())
elif last_res and not changed:
    print "The IP Identification field was not modified between you and the last router that replied (%s)." % (last_res.router())
