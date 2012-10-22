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
    name = 'swindow'
    operator_name = 'swindow'
    operator_constructors = [(lambda x: x,),
                             (lambda x: x, int),
                             (lambda x: x, int, float)]
    def __init__(self, inputs, 
                 group_operator,
                 chunk_length=10,
                 chunk_delay=1,
                 snap_times=True,
                 inclusive=(True, False),
                 skip_empty=True):
        self.bucket_op = group_operator(inputs)
        self.chunk_length = chunk_length
        self.chunk_delay = chunk_delay
        self.snap_times = snap_times
        self.skip_empty = skip_empty
        self.name = "swindow(%s, chunk_length=%i, chunk_delay=%f)" % (
            str(self.bucket_op), self.chunk_length, self.chunk_delay)
        Operator.__init__(self, inputs, outputs=self.bucket_op.outputs)
        self.pending = [null] * len(self.outputs)

    def process(self, input):
        # store the new data
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
                       if len(x) else [],
                       self.pending)

            # skip window if there's no data in it
            if self.skip_empty and sum(map(len, data)) == 0: continue
            data = [x if len(x) else np.array([[time, np.nan]]) for x in data]

            # apply
            opresult = self.bucket_op(data)
            if max(map(len, opresult)) > 1:
                raise core.SmapException("Error! Grouping operators can not produce "
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

def P(x):
    return map(lambda i: [x] * i, xrange(0, 5))

class GroupByDatetimeField(Operator):
    """Grouping operator which works using datetime objects

    usage:
       window($1, group_operator(), field="day", 
              width=1, increment=None)

    This operator first bins data in the time dimension using datetime
    objects; for instance, if you say field = "day", the operator will
    bin all points from the same data (and month and year).  It then
    applies the group operator to these bins; these are typically
    operators like max, min, or mean; something which summarizes the
    contents of the bin.

    The window width defaults to one.  Is the number of units of the
    "field" to include in a window -- that is, field="minute",
    width=15 would create 15-minute buckets.

    The window increment determines how far forward the begining of
    the window advances each time; by default, increment=width.  This
    can be used to implement sliding-window filters.
    """ 
    name = 'window'
    operator_name = 'window'
    operator_constructors = [(lambda x: x,)]
    DT_FIELDS = ['year', 'month', 'day', 'hour', 'minute', 'second']
    def __init__(self, inputs, group_operator, **kwargs):
        field = kwargs.get('field', 'day') 
        width = int(kwargs.get("width", 1))
        slide = int(kwargs.get("slide", width))
        inclusive = make_inclusive(kwargs.get("inclusive", "inc-exc"))
        snap_times = bool(kwargs.get("snap_times", True))
        if not field in self.DT_FIELDS:
            raise core.SmapException("Invalid datetime field: " + field)
        if not slide <= width:
            raise core.SmapException("window: Cannot slide more than the window width!")

        self.inclusive = make_inclusive(inclusive)
        if self.inclusive[0] == False:
            raise core.SmapException("Open intervals at the start are not supported")

        self.tzs = map(lambda x: dtutil.gettz(x['Properties/Timezone']), inputs)
        self.ops = map(lambda x: group_operator([x]), inputs)
        # self.ops = [[op([x]) for op in ops] for x in inputs]
        self.comparator = self.make_bin_comparator(field, width)
        self.snapper = self.make_bin_snapper(field, slide)
        self.snap_times = snap_times
        self.bin_width = datetime.timedelta(**{field + 's': width})
        self.bin_slide = datetime.timedelta(**{field + 's': slide})
        self.name = "window(%s, field=%s, width=%i, inclusive=%s, snap_times=%s)" % ( \
            str(self.ops[0]), field, width, str(inclusive), str(snap_times))
        Operator.__init__(self, inputs, 
                          util.flatten(map(operator.attrgetter('outputs'), 
                                           self.ops)))
        self.reset()

    def reset(self):
        self.state = [{}] * len(self.inputs)

    def make_bin_comparator(self, field, width):
        td = datetime.timedelta(**{field + 's': width})
        if self.inclusive[1] == False:
            cmp = operator.__lt__
        else:
            cmp = operator.__le__
        def comparator(ref, point):
            return cmp(point - ref, td)
        return comparator

    def make_bin_snapper(self, field, width):
        field_idx = self.DT_FIELDS.index(field)
        def snapper(point):
            kwargs = {}
            for f in self.DT_FIELDS[field_idx+1:]:
                kwargs[f + 's'] = getattr(point, f)

            # snap the final bin differently.
            fval = getattr(point, self.DT_FIELDS[field_idx])
            kwargs[self.DT_FIELDS[field_idx] + 's'] = \
                int(fval % width)
            td = datetime.timedelta(**kwargs)
            # print point, td
            return point - td
        return snapper

    def process_one(self, data, op, tz,
                    prev=None,
                    prev_datetimes=None):
        # print "PRCESSING"
        tic = time.time()
        if prev == None:
            prev = np.copy(data)
            prev_datetimes = MaskedDTList(prev[:, 0], tz)
        else:
            prev = np.vstack((prev, data))
            prev_datetimes.extend(data[:, 0])
        
        assert len(prev_datetimes) == len(prev)
        output = [null] * len(op.outputs)
        # output = [null] * len(util.flatten(map(operator.attrgetter("outputs"), ops)))
        # print output

        if len(prev_datetimes) == 0:
            return output, {
                'prev': prev,
                'prev_datetimes': prev_datetimes,
                }

        # find all the blocks in the time window.
        bin_start, truncate_to = self.snapper(prev_datetimes[0]), 0
        # print bin_start
        while True:
            bin_end = bin_start + self.bin_slide

            # perform a binary search to find the next window boundary
            bin_start_idx = bisect.bisect_left(prev_datetimes, bin_start) 
            bin_end_idx = bisect.bisect_left(prev_datetimes, bin_end)
            truncate_to = bin_start_idx

            # ignore bins which aren't full
            if bin_end_idx == len(prev_datetimes): break
            # skip empty bins
            if bin_start_idx == bin_end_idx: 
                bin_start += self.bin_slide
                continue

            if self.comparator(bin_start, prev_datetimes[bin_end_idx]):
                take_end = bin_end_idx + 1
            else:
                take_end = bin_end_idx

            opdata = op([prev[bin_start_idx:take_end, :]])
#             opdata = [op([prev[bin_start_idx:take_end, :]]) for op in ops]
#             opdata = util.flatten(opdata)
#             print "THAT", opdata
# #             print [opdata[0][:, 0]]
# #             print [o[:, 1:] for o in opdata]
#             opdata = [np.column_stack([opdata[0][:, 0]] + [o[:, 1:] 
#                                                            for o in opdata])]
#             print "THIS ONE", opdata
            
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

            bin_start += self.bin_slide

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
    """Group streams by values of a shared tag

    Usage: tgroup(<tag name>, <operator>)

    """
    operator_name = 'tgroup'
    operator_constructors = [(str, lambda x: x)]
    name = 'tgroup'

    def __init__(self, inputs, group_tag, group_operator):
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

        for o in self.operators:
            for i in xrange(0, len(o.outputs)):
                o.outputs[i]['Metadata/Extra/Operator'] = 'tgroup(%s, %s)' % (group_tag,
                                                                              str(o))
                                                                       
        self.block_streaming = reduce(operator.__or__,
                                      map(operator.attrgetter('block_streaming'), 
                                          self.operators))
        Operator.__init__(self, inputs, 
                          outputs=util.flatten(map(operator.attrgetter('outputs'), 
                                                   self.operators)))

    def process(self, data):
        rv = [[] for x in xrange(0, len(self.operators))]
        for i, op in enumerate(self.operators):
            input_data = [data[j] for j in self.group_idx[i]]
            rv[i] = self.operators[i](input_data)
        return util.flatten(rv)

class _OrderedOperator(Operator):
    def __init__(self, inputs, sort=None, reverse=False):
        # set default sort differently for the different methods
        if sort:
            keys = zip(map(operator.itemgetter(sort), inputs), range(0, len(inputs)))
            keys.sort(key=lambda x: x[0], reverse=reverse)
            self.order = map(operator.itemgetter(1), keys)
        else:
            self.order = None
        self.name = '%s(sort=%s, reverse=%s)' % (self.operator_name, 
                                                 str(sort), 
                                                 str(reverse))
        Operator.__init__(self, inputs)

    def process(self, data):
        if not self.order:
            return self._process(data)
        else:
            return self._process(map(lambda i: data[i], 
                                     self.order))



class PasteOperator(_OrderedOperator):
    """A special operator which returns a matrix (not the usual time
    series) of data.

 sort='uuid': specify a tag name whose value will be used to determine
    what order the columns in the matrix will be performed in.
 reverse=False: reverse the sorted order.

    The resulting matix has the columns of inputs joined on timestamp
    -- each row corresponds to a timestamp in one or more of the
    inputs timeseries.  If not all streams have data at a particular
    timestamp, a NaN value is inserted to indicate the missing data.
    """
    name = "paste"
    operator_name = "paste"
    operator_constructors = [()]

    def __init__(self, inputs, sort='uuid', reverse=False):
        return _OrderedOperator.__init__(self, inputs, sort=sort, reverse=reverse)

    def _process(self, data):
        return [transpose_streams(join_union(data))]


class HstackOperator(_OrderedOperator):
    """An operator which stacks all of the input data horizontally.
    All input vectors must have the same length for this to work.  The
    output timeseries has timestamps which come from the first column;
    the order columns are concatinated in may be controled with the
    sort and reverse keyword arguments, as with paste.
    """

    name = "hstack"
    operator_name = "hstack"
    operator_constructors = [()]

    # set default kwargs
    def __init__(self, inputs, sort=None, reverse=False):
        return _OrderedOperator.__init__(self, inputs, sort=sort, reverse=reverse)

    def _process(self, data):
        lengths = set((x.shape[0] for x in data))
        if len(lengths) != 1:
            raise core.SmapException("paste: hstack: wrong sized inputs")
        return [np.hstack([data[0]] + map(lambda x: x[:, 1:], data[1:]))]


class ReshapeOperator(ParallelSimpleOperator):
    name = "reflow"
    operator_name = "reflow"
    operator_constructors = [(int,)]

    def __init__(self, inputs, height):
        ParallelSimpleOperator.__init__(self, inputs, height=height)

    @staticmethod
    def base_operator(data, height=1, buf=null):
        buf = np.vstack((buf, data))
        cols = buf.shape[0] / height
        end = buf.shape[0] - (buf.shape[0] % height)
        return (np.column_stack((buf[:height, 0], 
                                 np.reshape(np.transpose(buf[:end, 1:]), 
                                            (height, cols),
                                            order='F'))),
                {'buf': buf[end:, :],
                 'height': height})


class VectorizeOperator(Operator):
    """An operator which applies multiple operators in on the same data.

    This operator multiples the number of timeseries by the number of
    operators present -- to combine in a matrix, you should generally
    use paste or hstack.

    For instance, you could use this to compute multiple statistics about your data:

    window(hstack < vectorize(min, max), field="hour")

    This operator computes hourly minimum and maximum values of data
    within the window as a single time series -- the first column will
    contain the minimum and the second the maximum.
    """
    name = "vectorize"
    operator_name = "vectorize"
    operator_constructors = []

    def __init__(self, inputs, *oplist):
        self.ops = [op(inputs) for op in oplist]
        self.name = "%s(%s)" % (self.operator_name, ','.join(map(str, self.ops)))
        self.block_streaming = reduce(operator.__or__, 
                                      (op.block_streaming for op in self.ops), 
                                      False)
        print "blocking", self.block_streaming
        Operator.__init__(self, inputs, 
                          util.flatten(map(operator.attrgetter('outputs'), 
                                           self.ops)))

    def process(self, data):
        return util.flatten(op(data) for op in self.ops)

for n in xrange(0, 10):
    VectorizeOperator.operator_constructors.append(tuple([lambda _: _] * n))

