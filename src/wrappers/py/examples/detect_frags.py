#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

def last_reply(r):
    ret = 1
    for ttl, res in r.iteritems():
        if res:
            ret = ttl
    return ret

res_no_frag = get_tracebox(probe)
l = last_reply(res_no_frag)

frags = fragment(probe, 8)
res = []
for i in range(len(frags)):
    res.append(get_tracebox(frags[i], nprobes = 1))

r = [last_reply(_r) for _r in res]
if r[-1] < l:
    print res_no_frag[r[-1]].router() + " does not seem to accept fragmented packets."
elif len(set(r)) != 0:
    print res_no_frag[min(r)].router() + " seem to reassemble the packets."
