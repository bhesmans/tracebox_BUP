#!/usr/bin/env python

import args
import tracebox, random
from scapy.all import IP, TCP

dest = args.parse_args()

probe = IP(dst=dest, proto="tcp", id=random.randint(0, 2**16-1)) / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=80, flags="S").build()

for ttl, res in tracebox.trace("%s" % probe).iteritems():
    if not res:
        continue
    if res.is_full_reply():
        print res.router()
