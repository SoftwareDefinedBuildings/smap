
import os
import time
import re
import json
import uuid
import errno
import cPickle as pickle
import ConfigParser
import traceback as trace

from zope.interface import implements
from twisted.internet.task import cooperate
from twisted.internet import task, reactor, threads, defer
from twisted.python.lockfile import FilesystemLock
from twisted.web import iweb
from twisted.python import log

import core

try:
    import cjson
    json_encode = cjson.encode
    json_decode = cjson.decode
except ImportError:
    json_encode = json.dumps
    json_decode = json.loads

is_string = lambda x: isinstance(x, str) or isinstance(x, unicode)
is_integer = lambda x: isinstance(x, int) or isinstance(x, long)

def now():
    return int(time.time())

def split_path(path):
    path = re.split('/+', path)
    return filter(lambda x: len(x), path)

def join_path(path):
    return '/' + '/'.join(path)

norm_path = lambda x: join_path(split_path(x))

def str_path(s):
    """Make a string appropriate to be a path compnent"""
    return s.lower().replace(' ', '_').replace('/', '_')

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
            if len(fullname):
                rv += buildkv(fullname + '/' + newk, newv)
            else:
                rv += buildkv(newk, newv)
        return rv
    else:
        return [(fullname, obj)]

# make a nested object from a config file line
def build_recursive(d, suppress=['type', 'key', 'uuid']):
    rv = {}
    for k, v in d.iteritems():
        if k in suppress: continue
        pieces = k.split('/')
        cur = rv
        for cmp in pieces[:-1]:
            if not cur.has_key(cmp):
                cur[cmp] = {}
            cur = cur[cmp]
        cur[pieces[-1]] = v
    return rv

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
#     lock = FilesystemLock(filename + ".lock")
#     if not lock.lock():
#         raise SmapException("Could not acquire report file lock")

    try:
        fp = open(filename, 'rb')
    except IOError:
#         lock.unlock()
        return None

    try:
        return pickle.load(fp)
    except (IOError, EOFError, pickle.PickleError), e:
        print e
        return None
    finally:
        fp.close()
#         lock.unlock()

def pickle_dump(filename, obj):
    """Pickle an object to a gzipped file while holding a filesystem
    lock.
    """
    if not filename:
        return

    try:
        fp = open(filename + '.tmp', 'wb')
        pickle.dump(obj, fp, protocol=2)
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
    except OSError, e:
        # Windows versions prior to Vista don't support atomic renames
        if e.errno != errno.EEXIST:
            raise
        os.remove(filename)
        os.rename(filename + '.tmp', filename)
    except IOError, e:
        trace.print_exc()
        pass

def periodicCallInThread(fn, *args):
    """Periodically enqueue a task to be run in the ``twisted``
threadpool (not in the main loop).  You'll need to call the
``start(interval)`` method on the return.  Multiple copies may run
concurrently, depending on the thread pool size if you do not finish
fast enough.

:param fn: the function to be called
:param args: arguments to be passed to `fn`
:rtype: the :py:class:`twisted.internet.task.LoopingCall` result
    """
    return task.LoopingCall(lambda: reactor.callInThread(fn, *args))

class PeriodicCaller:
    """The problem with doing a LoopingCall and then deferring to a
    thread is that you might have multiple copies of your function
    running simultaneously.  There are a variety of reasons this might
    be undesirable, so you can use this class instead, which will wait
    for a previous invocation to complete before running the next one.
    """
    def __init__(self, fn, args):
        self.fn, self.args = fn, args

    def _go(self):
        # bad things seem to happen when we throw an exception in the
        # thread pool... let's catch that and just log it
        try:
            self.fn(*self.args)
        except:
            log.err()
        
    def _run(self):
        self.last = time.time()
        d = threads.deferToThread(self._go)
        d.addCallbacks(self._post_run)

    def _post_run(self, result):
        now = time.time()
        sleep_time = self.interval - (now - self.last)
        if sleep_time < 0:
            self._run()
        else:
            reactor.callLater(sleep_time, self._run)

    def start(self, interval, now=True):
        self.interval = interval
        self.last = time.time()
        if now:
            self._run()
        else:
            reactor.callLater(self.interval, self._post_run, None)


def periodicSequentialCall(fn, *args):
    """Periodically run `fn(*args)` in a threadpool.  unlike
:py:func:`~smap.util.periodicCallInThread`, will not run your task
concurrently with itself -- if the last invocation didn't finish in
time for your next execution, it will wait rather than running it in a
different thread.

You also need to call `start(interval)` on the result.
    """
    return PeriodicCaller(fn, args)


def syncMaybeDeferred(fn, *args):
    """Version of maybeDeferred which calls fn(*args) immediately,
    rather than from the event loop as the library version does.
    """
    rv = fn(*args)
    if issubclass(rv.__class__, defer.Deferred):
        return state
    else:
        return defer.succeed(rv)


if __name__ == '__main__':
    import sys
    log.startLogging(sys.stdout)
    def cb(st):
        print "db running, sleeping", st
        raise Exception('foo')
        time.sleep(st)
    periodicSequentialCall(cb, 3).start(2.5)
    reactor.run()
