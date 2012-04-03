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


import datetime
import operator
import numpy as np
import time
import bisect

from twisted.python import log

from smap import util, core
from smap.operators import *
from smap.ops.util import PrintOperator, MaskedDTList
from smap.contrib import dtutil

def make_inclusive(range):
    if util.is_string(range):
        if range == 'inclusive': range = (True, True)
        elif range == 'inc-exc': range = (True, False)
        else: raise core.SmapException("Unsupported range: " + range)
    return range

class GroupByTimeOperator(Operator):
    """Time grouping operator.  Divide time into windows, and call
    group_operator on all the data in each window; return the result.
    The group_operator must return a single reading on each output
    stream.

    chunk_length: the size of the windows time is chunked into
    chunk_delay: when we call the group operator.
    """
    name = "latest buffer operator"
    operator_name = 'swindow'
    operator_constructors = [(lambda x: x,),
                             (lambda x: x, int)]
    def __init__(self, inputs, 
                 group_operator,
                 chunk_length=10,
                 chunk_delay=1,
                 snap_times=True,
                 inclusive=(True, False)):
        self.bucket_op = group_operator(inputs)
        Operator.__init__(self, inputs, outputs=self.bucket_op.outputs)
        self.pending = [null] * len(self.outputs)
        self.chunk_length = chunk_length
        self.chunk_delay = chunk_delay
        self.snap_times = snap_times

    def process(self, input):
        # store the new data
        # print "processing..."
        self.pending = extend(self.pending, input)

        # apply the grouping operator to each window
        startts = min(map(lambda x: np.min(x[:, 0]) if len(x) else np.inf,
                          self.pending))
        endts = max(map(lambda x: np.max(x[:, 0]) if len(x) else 0, 
                        self.pending))
        rv = [null] * len(self.outputs)

        if startts == np.inf or endts == 0:
            return rv

        startts = int(startts - (startts % self.chunk_length))
        endts = int((endts - (endts % self.chunk_length)) - \
                        (self.chunk_length * self.chunk_delay))
 
        # iterate over the groups
        for time in xrange(startts, endts, self.chunk_length):
            # print "group starting", time
            data = map(lambda x: x[np.where((x[:,0] >= time) & 
                                            (x[:,0] < time + self.chunk_length))] 
                       if len(x) else np.array([[time, np.nan]]),
                       self.pending)
            data = [x if len(x) else np.array([[time, np.nan]]) for x in data]
            # apply
            opresult = self.bucket_op(data)
            if max(map(len, opresult)) > 1:
                raise SmapException("Error! Grouping operators can not produce "
                                    "more than one result per group!")
            if self.snap_times:
                for x in opresult:
                    x[:, 0] = time
            rv = extend(rv, opresult)

        # filter out the data we operated on
        self.pending = map(lambda x: x[np.nonzero(x[:, 0] >= endts)]
                           if len(x) else null, 
                           self.pending)

        return rv


class GroupByDatetimeField(Operator):
    """Grouping operator which works using datetime objects

    usage:
       date_window($1, group_operator(), field="day", increment=1)

    This operator first bins data in the time dimension using datetime
    objects; for instance, if you say field = "day", the operator will
    bin all points from the same data (and month and year).  It then
    applies the group operator to these bins; these are typically
    operators like max, min, or mean; something which summarizes the
    contents of the bin.
    """ 
    name = 'group by datetime'
    operator_name = 'window'
    operator_constructors = [(lambda x: x,)]
    DT_FIELDS = ['year', 'month', 'day', 'hour', 'minute', 'second']
    def __init__(self, inputs, group_operator, field='day', 
                 increment=1, inclusive=(True, False),
                 snap_times=True):
        if not field in self.DT_FIELDS:
            raise core.SmapException("Invalid datetime field: " + field)

        self.inclusive = make_inclusive(inclusive)
        if self.inclusive[0] == False:
            raise core.SmapException("Open intervals at the start are not supported")

        self.tzs = map(lambda x: dtutil.gettz(x['Properties/Timezone']), inputs)
        self.ops = map(lambda x: group_operator([x]), inputs)
        self.comparator = self.make_bin_comparator(field, increment)
        self.snapper = self.make_bin_snapper(field, increment)
        self.snap_times = snap_times
        self.bin_width = datetime.timedelta(**{field + 's': increment})
        Operator.__init__(self, inputs, 
                          util.flatten(map(operator.attrgetter('outputs'), 
                                           self.ops)))
        self.reset()

    def reset(self):
        self.state = [{}] * len(self.inputs)

    def make_bin_comparator(self, field, increment):
        td = datetime.timedelta(**{field + 's': increment})
        if self.inclusive[1] == False:
            cmp = operator.__lt__
        else:
            cmp = operator.__le__
        def comparator(ref, point):
            return cmp(point - ref, td)
        return comparator

    def make_bin_snapper(self, field, increment):
        field_idx = self.DT_FIELDS.index(field)
        def snapper(point):
            kwargs = {}
            for f in self.DT_FIELDS[field_idx+1:]:
                kwargs[f + 's'] = getattr(point, f)

            # snap the final bin differently.
            fval = getattr(point, self.DT_FIELDS[field_idx])
            kwargs[self.DT_FIELDS[field_idx] + 's'] = \
                int(fval % increment)
            td = datetime.timedelta(**kwargs)
            # print point, td
            return point - td
        return snapper

    def process_one(self, data, op, tz,
                    prev=None,
                    prev_datetimes=None):
        tic = time.time()
        if prev == None:
            prev = np.copy(data)
            prev_datetimes = MaskedDTList(prev[:, 0], tz)
        else:
            prev = np.vstack((prev, data))
            prev_datetimes.extend(data[:, 0])
        
        assert len(prev_datetimes) == len(prev)
        output = [null] * len(op.outputs)

        if len(prev_datetimes) == 0:
            return output, {
                'prev': prev,
                'prev_datetimes': prev_datetimes,
                }

        # find all the blocks in the time window.
        bin_start, bin_start_idx, truncate_to = self.snapper(prev_datetimes[0]), 0, 0
        # print bin_start
        while True:
            bin_end = bin_start + self.bin_width

            # perform a binary search to find the next window boundary
            bin_end_idx = bisect.bisect_left(prev_datetimes, bin_end)
            if bin_end_idx == len(prev_datetimes): break
            if bin_start_idx == bin_end_idx: 
                # skip empty bins
                bin_start = bin_end
                continue
            truncate_to = bin_end_idx

            if self.comparator(bin_start, prev_datetimes[bin_end_idx]):
                take_end = bin_end_idx + 1
            else:
                take_end = bin_end_idx

            opdata = op([prev[bin_start_idx:take_end, :]])
            
            # snap the times to the beginning of the
            # window, if we were asked to.  do this here
            # so we can avoid passing datetimes around,
            # and deal with the common case where this is
            # what ya want.
            if self.snap_times:
                t = dtutil.dt2ts(bin_start)
                for j in xrange(0, len(opdata)):
                       opdata[j][:, 0] = t
            output = extend(output, opdata)

            bin_start = bin_end
            bin_start_idx = bin_end_idx

        toc = time.time()
#         print("dt processing took %0.05f: %i/%i converted" %  \
#                   (toc-tic,
#                    prev_datetimes.conversions,
#                    len(prev_datetimes)))

        prev_datetimes.truncate(truncate_to)
        prev = prev[truncate_to:]

        return output, {
            'prev': prev,
            'prev_datetimes': prev_datetimes,
            }

    def process(self, data):
        rv = [null] * len(self.inputs)
        for i in xrange(0, len(self.inputs)):
            rv[i], self.state[i] = self.process_one(data[i],
                                                    self.ops[i],
                                                    self.tzs[i],
                                                    **self.state[i])
        # flatten the individual stream results
        rv = util.flatten(rv)
        # now we have to insert nans to indicate missing data so the
        # rows from all streams are aligned.
        return join_union(rv)
        

class GroupByTagOperator(Operator):
    """Group streams by values of a shared tag"""
    operator_name = 'tag_group'
    operator_constructors = [(lambda x: x, str)]

    def __init__(self, inputs, group_operator, group_tag):
        groups = [None]
        self.group_idx = [[]]
        group_inputs = [[]]
        # compute 
        for i, s in enumerate(inputs):
            if not s.get(group_tag, None) in groups:
                groups.append(s[group_tag])
                self.group_idx.append(list())
                group_inputs.append(list())

            g_idx = groups.index(s.get(group_tag, None))
            group_inputs[g_idx].append(s)
            self.group_idx[g_idx].append(i)


        self.operators = [group_operator(x) if len(x) else PrintOperator([])
                          for x in group_inputs]

        Operator.__init__(self, inputs, 
                          outputs=util.flatten(map(operator.attrgetter('outputs'), 
                                                   self.operators)))

    def process(self, data):
        rv = [[] for x in xrange(0, len(self.operators))]
        for i, op in enumerate(self.operators):
            input_data = [data[j] for j in self.group_idx[i]]
            rv[i] = self.operators[i](input_data)
        return util.flatten(rv)

class PasteOperator(Operator):
    """A special operator which returns a matrix (not the usual time
    series) of data with NaNs inserted to mark missing data"""
    name = "paste"
    operator_name = "paste"
    operator_constructors = [()]

    def __init__(self, inputs, sort=None, reverse=False):
        if sort:
            keys = zip(map(operator.itemgetter(sort), inputs), range(0, len(inputs)))
            keys.sort(key=lambda x: x[0], reverse=reverse)
            self.order = map(operator.itemgetter(1), keys)
        else:
            self.order = None
        Operator.__init__(self, inputs)

    def process(self, data):
        if not self.order:
            return [transpose_streams(join_union(data))]
        else:
            return [transpose_streams(join_union(map(lambda i: data[i], 
                                                     self.order)))]


class GroupingPasteOperator(Operator):
    """An operator which allows us to apply different operators to
    groups of data"""

    def __init__(self, groups):
        """groups: a list of (key, operator) tuples responsible for eaach group
        """
        self.groups = groups

    def bind(self, group_inputs):
        """Bind the operator maps to specific inputs
        
        group_inputs: a map from the same key strings to the actual
            streams.  This step instantiates all the operators.
        """
        print "binding", group_inputs

    def process(self, data, push=False):
        print "PROCESS ME"
