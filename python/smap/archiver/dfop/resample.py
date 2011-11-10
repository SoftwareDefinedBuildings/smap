
import copy
import time
import unittest
import operator
from collections import namedtuple

StreamSet = namedtuple('StreamSet', 'data meta')

class PushableGenerator:
    def __init__(self, gen):
        self.gen = gen
        self.next_val = None
        self.has_next = False

    def __iter__(self):
        return self

    def next(self):
        if self.has_next:
            self.has_next = False
            return self.next_val
        else:
            return self.gen.next()

    def push(self, val):
        if not self.has_next:
            self.has_next = True
            self.next_val = val
        else:
            raise Exception("Can only push one value!")

def data_parallel(op):
    """decorator for functions which process each stream separately"""
    def real_op(streams, *args):
        return StreamSet([PushableGenerator(op(x, *args)) 
                          for x in streams.data], streams.meta)
    return real_op

def data_agg(op):
    """decorator for functions which read N input streams and produce
    a single output"""
    def real_op(streams, *args):
        return StreamSet([PushableGenerator(op(streams.data))], {'operator' : op.__doc__,
                                                                 'streams': streams.meta})
    return real_op

def mmin(row):
    try:
        return min((v[0] for v in row if v is not None))
    except ValueError:
        return float('-inf')

def mmax(row):
    try:
        return max((v[0] for v in row if v is not None))
    except ValueError:
        return float('inf')


def read_aligned(streams, ignore_missing=True):
    """read a set of records from a stream vector by reading points
    util a tuple is found where all the timestamps are the same.
    """
    row = [None] * len(streams)
    for idx in xrange(0, len(streams)):
        try:
            row[idx] = streams[idx].next()
        except StopIteration:
            row[idx] = None

    min_val = mmin(row)
    if min_val == float('-inf'):
        return []

    for i in xrange(0, len(row)):
        if row[i] == None: continue
        if row[i][0] > min_val:
            streams[i].push(row[i])
            row[i] = None

    return filter(None, row)


@data_parallel
def decimate(stream, n):
    """Decimate a stream by yielding only 1/N records"""
    idx = 0
    for v in stream:
        if idx % n == 0:
            yield v
        idx += 1

@data_parallel
def subsample(stream, windowsz, munge_times=True):
    """Subsample a stream by yielding only the first record within a window"""
    last = -1
    for v in stream:
        base = v[0] - (v[0] % windowsz)
        if base > last:
            if munge_times:
                new = (base,) + tuple(v[1:])
            else:
                new = v
            last = base
            yield new

@data_parallel
def count(stream):
    cnt = 0
    for v in stream: 
        cnt += 1
    yield (cnt,)

@data_agg
def dfsum(streams, ignore_missing=True):
    """sum"""
    while 1:
        row = read_aligned(streams, ignore_missing)
        if len(row) > 0:
            val = reduce(operator.__add__, map(operator.itemgetter(1), row), 0)
            yield (row[0][0], val, len(row))
        else:
            break

operators = {
    'count' : (count, []),
    'decimate' : (decimate, [int]),
    'subsample' : (subsample, [int]),
    'sum' : (dfsum, []),
    }


class TestSubSample(unittest.TestCase):
    def makeStream(self, start, end, step=1):
        return ((x,x) for x in xrange(start, end, step))

    def testOne(self):
        streams = StreamSet([self.makeStream(0, 10)], None)
        sub = subsample(streams, 3)
        self.assertEquals(len(sub.data), 1)
        next = 0
        for val in sub.data[0]:
            self.assertEquals(val[0], next)
            next += 3

    def testDecimate(self):
        streams = StreamSet([self.makeStream(0, 10)], None)
        sub = decimate(streams, 3)
        self.assertEquals(len(sub.data), 1)
        next = 0
        for val in sub.data[0]:
            self.assertEquals(val[0], next)
            next += 3

    def testCount(self):
        streams = StreamSet([self.makeStream(0, 10)], None)
        sub = count(streams)
        self.assertEquals(len(sub.data), 1)
        self.assertEquals(sub.data[0].next(), (10,))


    def testSumOne(self):
        streams = StreamSet([self.makeStream(0, 10)], None)
        sub = dfsum(streams)
        self.assertEquals(len(sub.data), 1)
        next = 0
        for val in sub.data[0]:
            self.assertEquals(val[0], next)
            next += 1

    def testSumTen(self):
        streams = StreamSet([self.makeStream(0, 10) for x in xrange(0, 10)], None)
        sub = dfsum(streams)
        self.assertEquals(len(sub.data), 1)
        next = 0
        for val in sub.data[0]:
            self.assertEquals(val[0], next)
            self.assertEquals(val[1], next * 10)
            next += 1

    def testSumMissing(self):
        streams = StreamSet([self.makeStream(0, 10) for x in xrange(0, 5)], None)
        streams.data.extend([self.makeStream(0, 5) for x in xrange(0, 5)])
        sub = dfsum(streams)
        self.assertEquals(len(sub.data), 1)
        next = 0
        for val in sub.data[0]:
            self.assertEquals(val[0], next)
            if next < 5:
                self.assertEquals(val[1], next * 10)
            else:
                self.assertEquals(val[1], next * 5)
            next += 1

class TestReadAligned(unittest.TestCase):
    def makeStream(self, start, end, step=1):
        return PushableGenerator(((x,) for x in xrange(start, end, step)))
    
    def assertTimes(self, row):
        for i in xrange(1, len(row) - 1):
            self.assertEquals(row[0][0], row[i][0])

    def testSimple(self):
        ss = [self.makeStream(0, 10) for x in range(0, 5)]
        for i in xrange(0, 10):
            row = read_aligned(ss)
            self.assertTimes(row)
            self.assertEquals(row[0][0], i)

    def testMissing(self):
        ss = [self.makeStream(0, 10) for x in range(0, 4)]
        ss.append(self.makeStream(0, 5))
        for i in xrange(0, 5):
            row = read_aligned(ss)
            self.assertTimes(row)
            self.assertEquals(row[0][0], i)

        for i in xrange(5, 10):
            row = read_aligned(ss)
            self.assertTimes(row)
            self.assertEquals(row[0][0], i)

    def testStagger(self):
        ss = [self.makeStream(x, 10) for x in range(0, 4)]
        for i in xrange(0, 3):
            row = read_aligned(ss)
            self.assertTimes(row)
            self.assertEquals(len(row), i+1)
            
        for i in xrange(3, 10):
            row = read_aligned(ss)
            self.assertTimes(row)
        row = read_aligned(ss)
        self.assertEquals(len(row), 0)

    def testCrazy(self):
        ss = [self.makeStream(0, 10), 
              self.makeStream(0, 10, 2)]
        for i in xrange(0, 10):
            row = read_aligned(ss)
            self.assertEquals(row[0][0], i)
            self.assertTimes(row)
            self.assertEquals(len(row), ((i+1) % 2) + 1)


if __name__ == '__main__':
    unittest.main()
