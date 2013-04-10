import _tracebox

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