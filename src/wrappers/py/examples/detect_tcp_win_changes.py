#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe_min_win = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, window = 0, flags="S").build()


probe_max_win = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, window = 2**16-1, flags="S").build()

last_res = None
changed = False
for probe in [probe_min_win, probe_max_win]:
    for ttl, res in do_tracebox(probe).iteritems():
        if not res:
            continue
        if res.tcp_rwin_changed():
            print "The TCP window field changed between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
            changed = True
        if res:
            last_res = res

if last_res and last_res.is_srv_reply() and not changed:
    print "The TCP window field was not modified between you and the destination (%s)." % (last_res.router())
elif last_res and not changed:
    print "The TCP window field was not modified between you and the last router that replied (%s)." % (last_res.router())
