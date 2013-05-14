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

import uuid
import time
import datetime
import calendar
import bisect
import numpy as np
from twisted.trial import unittest

from smap import operators, core
from smap.ops import grouping, arithmetic
from smap.ops import util as oputils
from smap.contrib import dtutil

def make_input_meta(n, extra_metadata={}):
    inputs = []
    for i in xrange(0, n):
        inp = {
            'uuid': str(uuid.uuid1()),
            'Properties/UnitofMeasure': ''
            }
        inp.update(extra_metadata)
        inputs.append(inp)
    return inputs

def make_test_data(n=2, len=20):
    data = map(lambda _: np.ones((len, 2)), xrange(0, n))
    for i in xrange(0, len):
        for j in xrange(0, n):
            data[j][i, 0] = i
            data[j][i, 1] = i * (j + 1)
    return data


class TestGroupByDatetime(unittest.TestCase):
    """Test the group by time operator"""
    hours = 60
    def setUp(self, now=1332546418):
        self.inputs = [{
                'uuid': str(uuid.uuid1()),
                'Properties/Timezone' : 'America/Los_Angeles'
                }]

        self.testdata = np.ones((self.hours, 2))
        for i in xrange(0, self.hours):
            self.testdata[i, :] = i
            
        self.testdata[:, 0] *= 3600 
        self.testdata[:, 0] += now 
        self.testdata[:, 0] *= 1000 # to ms

    def test_day(self):
        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.mean, field='day')
        outdata = op([self.testdata])
        self.assertEquals(len(outdata), 1)
        self.assertEquals(len(outdata[0]), (self.hours / 24) + 1)

    def test_hour(self):
        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.mean, field='hour')
        outdata = op([self.testdata])

        # don't get an output for the last hour
        self.assertEquals(len(outdata[0]), self.hours - 1)
        for i in xrange(0, len(outdata[0])):
            # should have only been one thing in each bucket
            self.assertEquals(outdata[0][i, 1], i)
            # make sure we snapped to the beginning of the window
            dt = datetime.datetime.utcfromtimestamp(outdata[0][i, 0] / 1000)
            self.assertEquals(dt.minute, 0)
            self.assertEquals(dt.second, 0)
            
    def test_offset(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)
        
        op = grouping.GroupByDatetimeField(self.inputs, oputils.NullOperator, field='day')
        for i in xrange(0, 24):
            rv = op([self.testdata[i:25+i, :]])
            self.assertEquals(rv[0].shape, (24 - i, 2))
            op.reset()

    def test_oneatatime(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

        op = grouping.GroupByDatetimeField(self.inputs, oputils.NullOperator, field='day')
        for i in xrange(0, 24):
            rv = op([self.testdata[i:i+1, :]])
            self.assertEquals(rv[0].shape, operators.null.shape)

        rv = op([self.testdata[24:25, :]])

        self.assertEquals(rv[0].shape, (24, 2))
        # make sure we snapped
        self.assertEquals(np.sum(rv[0][:, 0] - self.testdata[0, 0]), 0)
        # and got back the right data
        self.assertEquals(np.sum(rv[0][:, 1] - self.testdata[:24, 1]), 0)

    def test_inclusive(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

#         startshape = self.testdata.shape
#         startdata = np.copy(self.testdata)

#         op = grouping.GroupByDatetimeField(self.inputs, oputils.NullOperator, field='day')
#         rv = op([self.testdata[:30, :]])
#         self.assertEquals(rv[0].shape, (24, 2))
#         # check for mutations
#         self.assertEquals(self.testdata.shape, startshape)
#         self.assertEquals(np.sum(startdata - self.testdata), 0)

        op2 = grouping.GroupByDatetimeField(self.inputs, oputils.NullOperator, 
                                            field='day', inclusive=(True, True),
                                            snap_times=False)
        rv = op2([self.testdata[0:30, :]])
        self.assertEquals(rv[0].shape, (25, 2))
        self.assertEquals(rv[0][0, 0], self.testdata[0, 0])
        self.assertEquals(rv[0][24, 0], self.testdata[24, 0])

#         # push some more test data through!!!
#         rv = op2([self.testdata[30:60, :]])
#         self.assertEquals(rv[0].shape, (25, 2))
#         self.assertEquals(rv[0][0, 0], self.testdata[24, 0])
#         self.assertEquals(rv[0][24, 0], self.testdata[48, 0])
        
    def test_exceptions(self):
        self.assertRaises(core.SmapException, 
                          grouping.GroupByDatetimeField, self.inputs,
                          oputils.NullOperator,
                          field='__foo')
        self.assertRaises(core.SmapException, 
                          grouping.GroupByDatetimeField, self.inputs,
                          oputils.NullOperator,
                          inclusive="__foo")

    def test_increment(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

        for incr in [2, 4, 6, 8, 12, 24]:
            op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first, 
                                               field='hour', 
                                               width=incr)
            rv = op([self.testdata[:25, :]])
            # check the shape
            self.assertEquals(len(rv[0]), 24 / incr)
            for i in xrange(0, 24/incr):
                # the timestamps
                self.assertEquals(rv[0][i, 0], self.testdata[i * incr, 0])
                # and the values
                self.assertEquals(rv[0][i, 1], i * incr)
            del op

    def test_snap_times(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)
        
        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first, 
                                           field='day', 
                                           snap_times=True)
        rv = op([self.testdata[10:30]])
        self.assertEquals(rv[0][0, 0], self.testdata[0, 0])

    def test_snap_times_increment(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first, 
                                           field='hour',
                                           width=12,
                                           snap_times=True)
        rv = op([self.testdata[10:30, :]])
        self.assertEquals(len(rv[0]), 2)
        self.assertEquals(rv[0][0, 0], self.testdata[0, 0])
        self.assertEquals(rv[0][1, 0], self.testdata[12, 0])

    def test_slide(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first,
                                           field='hour',
                                           width=4,
                                           slide=2)
        rv = op([self.testdata])
        self.assertEquals(np.sum(rv[0][:, 0] - self.testdata[:-2:2, 0]), 0)
        self.assertEquals(np.sum(rv[0][:, 1] - self.testdata[:-2:2, 1]), 0)

    def test_flush(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)

        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first,
                                           field='hour',
                                           width=1)
        rv = op(operators.DataChunk((now * 1000, 
                                     now * 1000 + (self.hours * 3600 * 1000)), 
                                    True, True, 
                                    [self.testdata]))

        # if we don't properly flush the last hour, we should only get hours - 1 results
        self.assertEquals((rv[0][-1, 0] - (now *  1000)) / (3600 * 1000), self.hours - 1)

    def test_fill_missing(self):

        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)
        self.setUp(now)


        # check that we fill the end correctly
        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first,
                                           field='hour',
                                           width=1,
                                           skip_missing=False)
        now *= 1000
        rv = op(operators.DataChunk((now,
                                     now + ((self.hours + 5) * 3600 * 1000)), 
                                    True, True, 
                                    [self.testdata]))
        self.assertEqual(len(rv[0]), self.hours + 5)
        self.assertEqual(np.sum(np.isnan(rv[0][-5:, 1])), 5)
        self.assertEqual(np.sum(np.isnan(rv[0][:-5, 1])), 0)


        # and the beginning
        op = grouping.GroupByDatetimeField(self.inputs, arithmetic.first,
                                           field='hour',
                                           width=1,
                                           skip_missing=False)
        rv = op(operators.DataChunk((now - (5 * 3600 * 1000),
                                     now + ((self.hours) * 3600 * 1000)), 
                                    True, True, 
                                    [self.testdata]))
        self.assertEqual(len(rv[0]), self.hours + 5)
        self.assertEqual(np.sum(np.isnan(rv[0][:5, 1])), 5)
        self.assertEqual(np.sum(np.isnan(rv[0][5:, 1])), 0)



class TestMaskedDTList(unittest.TestCase):
    hours = 1000
    def setUp(self):
        now = dtutil.strptime_tz("1 1 2000 0", "%m %d %Y %H", tzstr="America/Los_Angeles")
        now = dtutil.dt2ts(now)

        self.testdata = np.ones((self.hours, 2))
        for i in xrange(0, self.hours):
            self.testdata[i, :] = i
            
        self.testdata[:, 0] *= 3600 
        self.testdata[:, 0] += now 
        self.ma = grouping.MaskedDTList(self.testdata[:, 0], dtutil.gettz("America/Los_Angeles"))
        self.width = datetime.timedelta(days=1)

    def test_basic(self):
        i = 0
        while i < len(self.ma):
            i = bisect.bisect_left(self.ma, self.ma[0] + self.width)
            self.assertEquals(self.ma[i], self.ma[0] + self.width)
            self.ma.truncate(i)

    def test_realpattern(self):
        i, start = 0, self.ma[0]
        while True:
            i = bisect.bisect_left(self.ma, start + self.width)
            if i >= len(self.ma): break
            self.assertEquals(self.ma[i], start + self.width)
            start += self.width

class TestJoins(unittest.TestCase):
    def setUp(self):
        self.data = [operators.null] * 2
        self.data[0] = np.ones((20, 2))
        self.data[1] = np.ones((20, 2))
        for i in xrange(0, 20):
            self.data[0][i, 0] = i
            self.data[1][i, 0] = i * 2

    def test_join_union(self):
        data = operators.join_union(self.data)
        for x in data:
            self.assertEquals(len(x), 30)
            for i in xrange(0, len(x)):
                # make sure the timestamps came out right
                if i < 20:
                    self.assertEquals(x[i, 0], i)
                else:
                    self.assertEquals(x[i, 0], (i - 10) * 2)
            # should check the outputs too... 

    def test_join_union_empty(self):
        # test if both inputs ar enull
        data = operators.join_union([operators.null, operators.null])
        for x in data:
            # they should have the same size as null, which is empty
            self.assertEquals(x.size, operators.null.size)
        
        # test if one of the inputs is null
        self.data[1] = operators.null
        data = operators.join_union(self.data)
        self.assertEquals(np.sum(data[0] - self.data[0]), 0)

        # the other stream should have copied timestamps from array 1
        self.assertEquals(np.sum(data[1][:, 0] - self.data[0][:, 0]), 0)
        # but only NaN's
        self.assertEquals(np.sum(np.isnan(data[1][:, 1])), len(data[1][:, 1]))


class TestTranspose(unittest.TestCase):
    len = 20
    def setUp(self):
        self.data = make_test_data(2)

    def test_simple(self):
        datas = operators.transpose_streams(self.data)
        self.assertEquals(np.sum(datas[:, 0] - self.data[0][:, 0]), 0)
        self.assertEquals(np.sum(datas[:, 1] - self.data[0][:, 1]), 0)
        self.assertEquals(np.sum(datas[:, 2] - self.data[1][:, 1]), 0)

class TestVectorOperator(unittest.TestCase):
    def setUp(self):
        self.TestClass = arithmetic.max
        self.inputs = make_input_meta(5)

    def test_stream_axis(self):
        """This is the default operator the vector operator uses"""
        op = self.TestClass(self.inputs, axis=1)
        self.assertEquals(op.block_streaming, False)
        data = make_test_data(5)
        rv = op(data)
        self.assertEquals(np.sum(rv[-1] - data[-1]), 0)

    def test_time_axis(self):
        op = self.TestClass(self.inputs, axis=1)
        self.assertEquals(op.block_streaming, False)
        data = make_test_data(5)
        rv = op(data)

    def test_streaming(self):
        """Check that block_streaming is twiddled appropriately"""
        self.assertEquals(self.TestClass(self.inputs, axis=0).block_streaming, True)
        self.assertEquals(self.TestClass(self.inputs, axis=1).block_streaming, False)

        self.assertEquals(arithmetic.count(self.inputs, axis=0).block_streaming, True)
        self.assertEquals(arithmetic.count(self.inputs, axis=1).block_streaming, False)
