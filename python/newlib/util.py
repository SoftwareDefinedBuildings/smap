"""Fun stuff to ease the pain.

class RateTimer: call a function at a constant rate, every N seconds.
 The function calls run synchronously and will not overlap if the rate
 is too fast.

http_load: read a json object at a url with simplified error handling:
 return None on any error.
"""


import time
import random
import threading
import urllib2
import logging
import socket
try:
    import simplejson as json
except ImportError:
    import json

class RateTimer(threading.Thread):
    """Implements a constant-rate timer: calls fn every period seconds
    without overlap if the executions are slow."""
    def __init__(self, period, fn):
        threading.Thread.__init__(self)
        self.fn = fn
        self.period = period
        self.daemon = True

    def run(self):
        last_exec = time.time() - (self.period * random.random())
        while True:
            sleep_time = last_exec + self.period - time.time()
            while sleep_time > 0:
                time.sleep(sleep_time)
                sleep_time = last_exec + self.period - time.time()
                
            last_exec = time.time()
            self.fn()

class FixedSizeList(list):
    """
    A class for keeping a circular buffer with a maximum size.
    Used for storing a fixed history of "profile" data.
    """
    def __init__(self, size=None, sort_profile=False):
        self.size = size
        self.sort_profile = sort_profile
        list.__init__(self)
    
    def append(self, val):
        if self.sort_profile == True:
            # Find insert point in sorted list
            idx = bisect.bisect_left([r.time for r in self], val.time)
            # Ignore duplicate times
            if idx >= len(self) or self[idx].time != val.time:
                self.insert(idx, val)
            else:
                return False
        else:
            list.append(self, val)

        if self.size and len(self) > self.size:
            self.pop(0)

        return True

    def set_size(self, size):
        if len(self) > size:
            self.__delslice__(0, self.size  - size)
        self.size = size

def http_load(url, data=None, timeout=5):
    """Simplified way to load an HTTP resource which yields a json object,
    and return the decoded object.  Returns None if there is any
    error.

    @data optional data to pass as a body in a POST request
    @url a string containing a url
    """
    log = logging.getLogger("http_loader")
    try:
        if data != None:
            fp = urllib2.urlopen(url, data=data, timeout=timeout)
        else:
            fp = urllib2.urlopen(url, timeout=timeout)
        obj = json.load(fp)
        return obj
    except ValueError, e:
        # json fail
        log.warn("JSON load fail: " + str(e))
        return None
    except urllib2.URLError, e:
        log.warn("URL error: " + str(e))
        return None
    except urllib2.HTTPError, e:
        log.warn("HTTP error: " + str(e))
        return None

def dict_filter(fn, d):
    del_list = []
    for k,v in d.iteritems():
        if not fn(k, v):
            del_list.append(k)
    map(d.__delitem__, del_list)
            
class socket_readline(socket.socket):
    def __init__(self, *args):
        socket.socket.__init__(self, *args)
        self.__buf = ""
        
    def readline(self, sep='\r\n'):
        # do a non-blocking read to pick up any buffered bytes
        self.__buf += self.recv(1024, socket.MSG_DONTWAIT)
        while self.__buf.find(sep) < 0:
            self.__buf += self.recv(1024)

        idx = self.__buf.find(sep)
        rv = self.__buf[:idx]
        self.__buf = self.__buf[idx+len(sep)+1:]
        return rv

if __name__ == '__main__':
    t = RateTimer(1, hello)
    t.start()
    time.sleep(10)
