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
import json
import logging

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

            
if __name__ == '__main__':
    t = RateTimer(1, hello)
    t.start()
    time.sleep(10)
