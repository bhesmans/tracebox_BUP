#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

source_port = random.randint(0, 2**16-1)
seq = random.randint(0, 2**32-1)

probe1 = IP(dst=dest, proto="tcp") / \
        TCP(seq=seq,
            sport=source_port,
            dport=dport, flags="S").build()

probe2 = IP(dst=dest, proto="tcp") / \
        TCP(seq=seq - 10,
            sport=source_port,
            dport=dport, flags="S").build()

probe3 = IP(dst=dest, proto="tcp") / \
        TCP(seq=seq - 20,
            sport=source_port,
            dport=dport, flags="S").build()

def length(res):
    last_r = 1
    for ttl, r in res.iteritems():
        if r and r.is_srv_reply():
            return ttl
        last_r = ttl
    return last_r

srv_ttl = length(do_tracebox(probe1))

# avoid reaching the destination -> creation of state in middlebox
res = do_tracebox(probe2, max_ttl = srv_ttl - 1)

# try to send a probe for the same 5-tuple but with a smaller seq num -> should be dropped by the middlebox
lp3 = length(do_tracebox(probe3))
if length(do_tracebox(probe3)) == srv_ttl:
    print "There are no statefull middlebox between you and the destination."
    sys.exit(0)

# resend first probe the server or us should send a RST
if length(do_tracebox(probe2)) != srv_ttl:
    print "An error happened"
    sys.exit(1)

if length(do_tracebox(probe3)) != srv_ttl:
    print "An error happened"
    sys.exit(1)
else:
    print "There is a statefull middlebox between you and the destination. (Suspect is %s)" % res[lp3].router()
    