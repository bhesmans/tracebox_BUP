#!/usr/bin/env python

import args
import tracebox, random
from scapy.all import IP, TCP

dest = args.parse_args()

probe = IP(dst=dest, proto="tcp", id=random.randint(0, 2**16-1)) / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=80, flags="S").build()

last_res = None
for ttl, res in tracebox.trace("%s" % probe).iteritems():
    if not res:
        continue
    print res.changed()
    if res.ip_id_changed():
        print "The IP Identification field changed between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
    if res:
        last_res = res

if last_res.is_srv_reply():
    print "The IP Identification field was not modified between you and the destination (%s)." % (last_res.router())
else:
    print "The IP Identification field wa not modified between you and the last router that replied (%s)." % (last_res.router())
