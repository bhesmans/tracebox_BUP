#!/usr/bin/env python

from args import *
import random, struct

dest, dport = parse_args()


def mp_capable(key = random.randint(0, 2**64-1)):
    return "\x00\x81" + struct.pack('!Q', key)

def probe_opt(opt = None):
    opts = [opt] if opt else []
    return IP(dst=dest, proto="tcp") / \
              TCP(seq=random.randint(0, 2**32-1),
                  sport=random.randint(0, 2**16-1),
                  dport=dport, flags="S", options = opts).build()

def length(res):
    for ttl, r in res.iteritems():
        if r and r.is_srv_reply():
            return ttl
    return len(res)

def opt_changed(r, orig):
    if not r:
        return not not orig
    return (not r.is_srv_reply() and (r.ip_tlen_changed() or r.tcp_opt_changed())) or (r.is_srv_reply() and r.tcp_opt_changed())

probe_no_opt = probe_opt()
probe_mss = probe_opt(("MSS", 9140))
probe_wscale = probe_opt(("WScale", 15))
probe_md5 = probe_opt((19, ''.join(chr(random.randint(0,255)) for _ in range(16))))
probe_mptcp = probe_opt((30, mp_capable()))

res_no_opt = get_tracebox(probe_no_opt)
path_length = length(res_no_opt)
res_mss = get_tracebox(probe_mss, max_ttl = path_length)
res_wscale = get_tracebox(probe_wscale, max_ttl = path_length)
res_md5 = get_tracebox(probe_md5, max_ttl = path_length)
res_mptcp = get_tracebox(probe_mptcp, max_ttl = path_length)

mss_changed = wscale_changed = md5_changed = mptcp_changed =  False

for ttl in range(1, path_length):
    mss_changed |= opt_changed(res_mss[ttl], res_no_opt[ttl])
    wscale_changed |= opt_changed(res_wscale[ttl], res_no_opt[ttl])
    md5_changed |= opt_changed(res_md5[ttl], res_no_opt[ttl])
    mptcp_changed |= opt_changed(res_mptcp[ttl], res_no_opt[ttl])

if mss_changed:
    print "The MSS option was changed/removed."
if wscale_changed:
    print "The Window Scale option was changed/removed."
if md5_changed:
    print "The MD5 signature option was changed/removed."
if mptcp_changed:
    print "The Multipath TCP option was changed/removed."

if opt_changed(res_mss[path_length], res_no_opt[path_length]):
    print "The destination did not reply with the MSS option."
if opt_changed(res_wscale[path_length], res_no_opt[path_length]):
    print "The destination did not reply with the Window Scale option."
if opt_changed(res_md5[path_length], res_no_opt[path_length]):
    print "The destination did not reply with the MD5 signature option."
if opt_changed(res_mptcp[path_length], res_no_opt[path_length]):
    print "The destination did not reply with the Multipath TCP option."