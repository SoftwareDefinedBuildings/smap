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

import numpy as np
import time
import traceback
import operator

from zope.interface import implements
from twisted.internet import interfaces, reactor, defer
from twisted.python import failure, log

import smap.util as util
import smap.sjson as json
import smap.operators as operators
from smap.ops import installed_ops, grouping
from smap.archiver import data
from smap.archiver import querygen as qg

def get_operator(name, args):
    """Look up an operator by name.  If given args, try to parse them
    using whatever initializer lists are available.

    :raises: ParseException if it can't match the operator
    """
    args, kwargs = args
    thisop = lookup_operator_by_name(name, args, kwargs)
    return thisop


def lookup_operator_by_name(name, args, kwargs):
    """Lookup an operator by name and return a closure which will
    instantiate the operator with the given args and kwargs"""
    if not name in installed_ops:
        raise qg.QueryException("No such operator: " + name)
    if len(args) == 0 and len(kwargs) == 0:
        # if the op doesn't take any args, just return the bare operator
        return installed_ops[name]
    else:
        for proto in installed_ops[name].operator_constructors:
            if len(proto) != len(args): continue
            try:
                alist = map(lambda (fn, a): fn(a), zip(proto, args))
                kwargs_ = kwargs
            except ValueError:
                continue

            return lambda inputs: installed_ops[name](inputs, *alist, **kwargs_)
        raise qg.QueryException("No valid constructor for operator %s: %s" % 
                                (name, str(args)))


class OperatorApplicator(object):
    """Make a closure that will apply the operator expresion to a
    specific set of streams and metadata."""
    implements(interfaces.IPushProducer)
    DATA_DAYS = 5

    def __init__(self, op, data_spec, consumer, group=None):
        self.op = op
        self.data_spec = data_spec
        self.group = group.pop() if group else None
        self.requester = data.DataRequester(ndarray=True, as_smapobj=False)
        self.consumer = consumer

        self._paused = self._stop = self._error = False
        self.chunk_idx, self.chunk_loaded_idx = 0, 0
        self.publish_lock = defer.DeferredLock()
        # print "creating opapp", op, data_spec, group
        consumer.registerProducer(self, True)

    def pauseProducing(self):
        self._paused = True

    def resumeProducing(self):
        self._paused = False
        try:
            # only start a new chunk if we're done loading our
            # existing chunks and we actually stopped doing anything
            # -- if we're still loading, load_chunk will be called
            # normally from the callback
            if (self.chunk_idx != None and 
                self.chunk_idx == self.chunk_loaded_idx):
                return self.load_chunk()
        except Exception, e:
            self.abort(failure.Failure(e))

    def stopProducing(self):
        self._stop = True

    def start_processing(self, data):
        """data: a list with two elements: the first is the metadata,
        and the second is the stream information we will need to fetch
        the actual data"""
        # save the metadata and streamids for loading
        opmeta = data[0][1]
        opmeta = map(lambda x: dict(util.buildkv('', x)), opmeta)
        if not len(opmeta):
            self.consumer.write([])
            self.consumer.unregisterProducer()
            self.consumer.finish()
            return 

        # sort the streamids to be in the same order as the operator inputs
        meta_uid_order = dict(zip(map(operator.itemgetter('uuid'), opmeta), 
                                  xrange(0, len(opmeta))))
        self.streamids = data[1][1]
        self.streamids.sort(key=lambda elt: meta_uid_order[elt[0]])

        # use a heuristic for how much data we want to load at once...
        self.chunk_length = (3600 * 24 * self.DATA_DAYS) / len(self.streamids)
        if self.chunk_length < 300:
            self.chunk_length = 300

        # build the operator
        if self.group and len(self.group):
            self.op = grouping.GroupByTagOperator(opmeta, 
                                                  self.group,
                                                  self.op)
        else:
            self.op = self.op(opmeta)
            for o in self.op.outputs:
                if not 'Metadata/Extra/Operator' in o:
                    o['Metadata/Extra/Operator'] = str(self.op)

        self.resumeProducing()

    def load_chunk(self):
        """load a chunk of data for the operator"""

        # this could happen if we were paused -- then load_chunk will
        # still get called by a callback but we'd be already done when
        # resumeProducing() is called.
        if self.chunk_idx == None: 
            return

        # decide on a new chunk to load
        start = (self.data_spec['start'] / 1000) + \
            (self.chunk_idx * self.chunk_length)
        end = (self.data_spec['start'] / 1000) + \
            ((self.chunk_idx+1) * self.chunk_length)
        start *= 1000
        end *= 1000
        last = False
        log.msg("starting chunk %i %i %s %s" % (self.chunk_idx, (end - start),
                                                time.ctime(start / 1000),
                                                time.ctime(end / 1000)))

        if self.op.block_streaming or end >= self.data_spec['end']:
            end = self.data_spec['end']
            last = True
            self.chunk_idx = None
        else:
            self.chunk_idx += 1

        self.args = {
            'starttime' : [start],
            'endtime' : [end],
            'limit' : [self.data_spec['limit'][0]],
            'streamlimit' : [self.data_spec['limit'][1]]
        }
        d = self.requester.load_data(self, 
                                     self.data_spec['method'], 
                                     self.streamids)
        if not last:
            d.addCallback(self.start_next)

        # once we've loaded the data, we need to acquire the
        # publish lock to actually send it to the consumer.  This
        # ensures we always write the results out in the correct order
        # (this depends on the DeferredLock being FIFO)
        dl = defer.DeferredList([self.publish_lock.acquire(), d])
        dl.addCallback(lambda result: result[1][1])
        dl.addCallback(self.apply_operator, (start, end), self.chunk_idx == 1, last)
        dl.addCallback(self.publish_data, last)
        dl.addBoth(lambda result: (self.publish_lock.release(), result)[1])
        dl.addErrback(self.abort)

    def abort(self, error):
        self._stop = True
        if hasattr(error, "getTraceback"):
            tb = str(error.getTraceback())
        else:
            tb = str(error)
        error = {
            'error': "Encountered error while reading data; results are incomplete",
            'exception': str(error.value),
            'traceback': tb,
            }
        log.msg(str(error))
        self.consumer.write(error)
        self.consumer.unregisterProducer()
        self.consumer.finish()
        return error

    def start_next(self, data):
        if not self._paused and not self._stop:
            self.load_chunk()
        return data

    def apply_operator(self, opdata, region, first, last):
        tic = time.time()
        self.chunk_loaded_idx += 1
        # process
        for d in opdata:
            d[:, 0] *= 1000

        opdata = operators.DataChunk(region, first, last, opdata)
        redata = self.op.process(opdata)

        log.msg("STATS: Operator processing took %0.6fs" % (time.time() - tic))
        # log.msg("writing " + str(map(len, redata)))
        # construct a return value with metadata and data merged
        return map(self.build_result, zip(redata, self.op.outputs))
        # print "processing and writing took", time.time() - tic

    def publish_data(self, data, last):
        if not self._stop: 
            self.consumer.write(data)
            if last:
                self.consumer.unregisterProducer()
                self.consumer.finish()

    def build_result(self, (d, s)):
        obj = dict(s)
        if isinstance(d, np.ndarray):
            obj['Readings'] = d.tolist()
        else:
            obj['Readings'] = d
        return util.build_recursive(obj, suppress=[])

