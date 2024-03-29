#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

for ttl, res in do_tracebox(probe):
    if not res:
        continue
    if res.is_full_reply() and not res.is_srv_reply():
        print ttl, res.router()
