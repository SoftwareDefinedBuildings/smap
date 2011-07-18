
import os
import time
import re
import simplejson as json
import uuid
import cPickle as pickle
import gzip
import ConfigParser
import traceback as trace

from zope.interface import implements
from twisted.internet.task import cooperate
from twisted.internet import task, reactor, threads
from twisted.python.lockfile import FilesystemLock
from twisted.web import iweb

import core

is_string = lambda x: isinstance(x, str) or isinstance(x, unicode)
is_integer = lambda x: isinstance(x, int) or isinstance(x, long)

def now():
    return int(time.time()) * 1000

def split_path(path):
    path = re.split('/+', path)
    return filter(lambda x: len(x), path)

def join_path(path):
    return '/' + '/'.join(path)

norm_path = lambda x: join_path(split_path(x))

class UuidEncoder(json.JSONEncoder):
    """The default UUID repr() isn't valid json; we just want the
        string representation for now anyways.
    """
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)

def dump_json(obj, fp):
    json.dump(obj, fp, cls=UuidEncoder)

def find(f, lst):
    for o in lst:
        if f(o): return o
    return None

def buildkv(fullname, obj):
    if isinstance(obj, dict):
        rv = []
        for newk, newv in obj.iteritems():
            rv += buildkv(fullname + '/' + newk, newv)
        return rv
    else:
        return [(fullname, obj)]

def dict_merge(o1, o2):
    """Recursively merge dict o1 into dict o2.  
    """
    if not isinstance(o1, dict) or not isinstance(o2, dict): 
        return o2
    o2 = dict(o2)
    for k, v in o1.iteritems():
        if k in o2:
            o2[k] = dict_merge(v, o2[k])
        else:
            o2[k] = v
    return o2

class FixedSizeList(list):
    """
    A class for keeping a circular buffer with a maximum size.
    Used for storing a fixed history of "profile" data.
    """
    def __init__(self, size=None, init=None, sort_profile=False, seqno=0):
        self.size = size
        self.seqno = seqno
        self.sort_profile = sort_profile
        if not init:
            init = []
        list.__init__(self, init)

    def __repr__(self):
        return "FixedSizeList(size=" + str(self.size) + \
            ", seqno=" + str(self.seqno) + ", init=" + \
            list.__repr__(self) + ")"


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
            self.seqno += 1

        if self.size and len(self) > self.size:
            self.pop(0)

        return True

    def extend(self, val):
        list.extend(self, val)
        self.seqno += len(val)
        if self.size and len(self) > self.size:
            self.reverse()
            del self[self.size:]
            self.reverse()

    def truncate(self, seq):
        """Remove first n values from the list"""
        rmpt = seq - (self.seqno - len(self) )
        if rmpt >= 0:
            del self[:rmpt]

    def set_size(self, size):
        if len(self) > size:
            self.__delslice__(0, self.size  - size)
        self.size = size

    def idxtoseq(self, idx):
        return self.seqno - len(self) + idx

# based on http://jcalderone.livejournal.com/55680.html
class AsyncJSON(object):
    implements(iweb.IBodyProducer)

    def __init__(self, value):
        self._value = value
        self.length = iweb.UNKNOWN_LENGTH

    def startProducing(self, consumer):
        self._consumer = consumer
        self._iterable = UuidEncoder().iterencode(self._value)
        self._task = cooperate(self._produce())
        d = self._task.whenDone()
        d.addBoth(self._unregister)
        return d

    def pauseProducing(self):
        self._task.pause()

    def resumeProducing(self):
        self._task.resume()

    def stopProducing(self):
        self._task.stop()

    def _produce(self):
        for chunk in self._iterable:
            self._consumer.write(chunk)
            yield None

    def _unregister(self, passthrough): 
        return passthrough

def pickle_load(filename):
    """Load an object from a gzipped pickle file while holding a
    filesystem lock
    """
    lock = FilesystemLock(filename + ".lock")
    if not lock.lock():
        raise SmapException("Could not acquire report file lock")

    try:
        fp = gzip.GzipFile(filename, 'rb')
    except IOError:
        lock.unlock()
        return None

    try:
        return pickle.load(fp)
    except (IOError, EOFError, pickle.PickleError), e:
        print e
        return None
    finally:
        fp.close()
        lock.unlock()

def pickle_dump(filename, obj):
    """Pickle an object to a gzipped file while holding a filesystem
    lock.
    """
    if not filename:
        return

    try:
        fp = gzip.GzipFile(filename + '.tmp', 'wb')
        pickle.dump(obj, fp, protocol=1)
    except (IOError, pickle.PickleError, TypeError), e:
        print "dump failure"
        trace.print_exc()
        return
    finally:
        os.fsync(fp)
        fp.close()

    try:
        # move it atomically if we were able to pickle the object
        os.rename(filename + '.tmp', filename)
    except IOError, e:
        trace.print_exc()
        pass
        

def periodicCallInThread(fn, *args):
    """Periodically enqueue a task to be run in the ``twisted``
threadpool (not in the main loop).  You'll need to call the
``start()`` method on the return.

:param fn: the function to be called
:param args: arguments to be passed to `fn`
:rtype: the :py:class:`twisted.internet.task.LoopingCall` result
    """
    return task.LoopingCall(lambda: reactor.callInThread(fn, *args))

