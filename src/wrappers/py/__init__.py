import _tracebox, pcapy, struct

from thread import start_new_thread
from Queue import Queue

def trace(probe, **kwargs):
    return _tracebox.trace(probe, **kwargs)

def itertrace(probe, **kwargs):
    ret = {}
    q = Queue()
    job_done = object()
    def callback(ttl, res):
        q.put((ttl,res))
    def producer():
        trace(probe, callback = callback, **kwargs)
        q.put(job_done)
    start_new_thread(producer,())
    while True:
        item = q.get()
        if item is job_done:
            break
        yield item

def replay(pcap_file):
    def get_ip_addrs(pkt):
        return struct.unpack("!II", pkt[12:20])
    def get_ttl(pkt):
        return struct.unpack("!B", pkt[8])[0]
    probe = None
    prev_ttl = ttl = None
    reader = pcapy.open_offline(pcap_file)
    while True:
        try:
            header, pkt = reader.next()
            probe = pkt if not probe else probe
            if get_ip_addrs(pkt) == get_ip_addrs(probe):
                ttl = get_ttl(pkt)
                continue
            res = _tracebox.replay(ttl, probe, pkt)
            if not prev_ttl:
                prev_ttl = ttl - 1
            for i in range(prev_ttl +1, ttl):
                yield (i, None)
            prev_ttl = ttl
            yield (ttl, res)
        except pcapy.PcapError:
            break
