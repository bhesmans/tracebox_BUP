#!/usr/bin/env python

from args import *
import random

dest, dport = parse_args()

probe = IP(dst=dest, tos = 0x2, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

last_res = None
changed = False
for ttl, res in do_tracebox(probe).iteritems():
    if not res:
        continue
    if res.ecn_changed() and not res.is_srv_reply():
        print "The ECN Capable flag has been reset between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
        changed = True
    if res.ecn_changed() and res.is_srv_reply():
        print "The destination did not reply with the ECN Capable flag"
    if res:
        last_res = res

if last_res and last_res.is_srv_reply() and not changed:
    print "The ECN Capable flag was not reset between you and the destination (%s)." % (last_res.router())
elif last_res and not changed:
    print "The ECN Capable flag was not reset between you and the last router that replied (%s)." % (last_res.router())

probe = IP(dst=dest, tos = 0x3, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="S").build()

last_res = None
changed = False
for ttl, res in do_tracebox(probe).iteritems():
    if not res:
        continue
    if res.ecn_changed() and not res.is_srv_reply():
        print "The Congestion Experienced flag has been reset between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
        changed = True
    if res.ecn_changed() and res.is_srv_reply():
        print "The destination did not reply with the Congestion Experienced flag"
    if res:
        last_res = res

if last_res and last_res.is_srv_reply() and not changed:
    print "The Congestion Experienced flag was not reset between you and the destination (%s)." % (last_res.router())
elif last_res and not changed:
    print "The Congestion Experienced flag was not reset between you and the last router that replied (%s)." % (last_res.router())


probe = IP(dst=dest, proto="tcp") / \
        TCP(seq=random.randint(0, 2**32-1),
            sport=random.randint(0, 2**16-1),
            dport=dport, flags="SEC").build()

last_res = None
changed = False
for ttl, res in do_tracebox(probe).iteritems():
    if not res:
        continue
    if res.tcp_flags_changed() and not res.is_srv_reply():
        print "The ECE flag has been reset between %s and %s(%d)" % (last_res.router() if last_res else "you", res.router(), ttl)
        changed = True
    if res:
        last_res = res

if last_res and last_res.is_srv_reply() and not changed:
    print "The ECE flag was not reset between you and the destination (%s)." % (last_res.router())
elif last_res and not changed:
    print "The ECE flag was not reset between you and the last router that replied (%s)." % (last_res.router())

