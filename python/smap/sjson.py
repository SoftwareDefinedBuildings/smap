"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import sys
import math
import uuid

from zope.interface import implements
from twisted.internet.task import cooperate
from twisted.web import iweb

try:
    import simplejson as json
except ImportError:
    if sys.version_info < (2, 7):
        print """WARNING: using json instead of simplejson: 
   this will be much slower on python < 2.7"""
    import json

class SmapEncoder(json.JSONEncoder):
    """The default UUID repr() isn't valid json; we just want the
        string representation for now anyways.
    """
    def default(self, obj):
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


def replace(obj):
    if isinstance(obj, float) and math.isnan(obj):
        return None
    elif isinstance(obj, dict):
        return dict(((k, replace(v)) for k, v in obj.iteritems()))
    elif isinstance(obj, list):
        return list((replace(v) for v in obj))
    else:
        return obj

def dumps(data):
    try:
        return json.dumps(data, cls=SmapEncoder, allow_nan=False)
    except ValueError:
        return json.dumps(replace(data), cls=SmapEncoder)

def dump(data, fp):
    return json.dump(data, fp, cls=SmapEncoder)

def loads(data):
    return json.loads(data)

def load(fp):
    return json.load(fp)

# based on http://jcalderone.livejournal.com/55680.html
class AsyncJSON(object):
    implements(iweb.IBodyProducer)
    content_type = 'application/json'
    content_encoding = None

    def __init__(self, value):
        self._value = value
        self.length = iweb.UNKNOWN_LENGTH

    def startProducing(self, consumer):
        self._consumer = consumer
        self._iterable = SmapEncoder().iterencode(self._value)
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


if __name__ == '__main__':
    import random
    import timeit

    N = 10

    tests = [
        ('cjson', 'cjson.encode(obj)'),
        ('json as j', 'j.dumps(obj)'),
        ('json as j', 'j.dumps(obj, allow_nan=False)'),
        ('simplejson', 'simplejson.dumps(obj)'),
        ('simplejson', 'simplejson.dumps(obj, allow_nan=False)'),
        ]

    setup = """
import random
import %s
obj = {
    'uuid': '1231' * 9,
    'Readings': [None] * 10000,
}
for i in xrange(0, 10000):
    obj['Readings'][i] = [i, float('nan')] # float(random.random() * 10000)]
    """

#     for (mod, enc) in tests:
#         t = timeit.Timer(stmt=enc, setup=setup % mod)
#         print '%s: %0.03f msec/pass (%s)' % (mod, 1000 * t.timeit(number=N) / N, enc)

    setup += """
from __main__ import dumps
"""
    t = timeit.Timer(stmt="dumps(obj)", setup=setup % 'json')
    print '%s: %0.03f msec/pass (%s)' % ('smap-json', 1000 * t.timeit(number=N) / N, 'SpecialEncoder')
