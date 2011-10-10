
import unittest
import operator

def data_parallel(op):
    """decorator for functions which process each stream separately"""
    def real_op(streams, *args):
        return map(lambda x: op(*args)(x), streams)
    return real_op

def data_agg(op):
    """decorator for functions which read N input streams and produce
    a single output"""
    def real_op(streams, *args):
        return [op(streams)]
    return real_op

def mmin(row):
    try:
        return min((v[0] for v in row if v is not None))
    except ValueError:
        return float('-inf')

def mmax(row):
    try:
        return min((v[0] for v in row if v is not None))
    except ValueError:
        return float('inf')

def read_aligned(streams, ignore_missing=True):
    """read a set of records from a stream vector by reading points
    util a tuple is found where all the timestamps are the same.
    """
    idx = 0
    row = [None] * len(streams)
    while (None in row or mmin(row) != mmax(row)):
        try:
            if row[idx] == None or row[idx][0] == mmin(row):
                row[idx] = streams[idx].next()
        except StopIteration:
            del streams[idx]
            del row[idx]
        if len(streams) == 0:
            break
        idx = (idx + 1) % len(streams)
    return row
    
#     idxs = range(0, len(streams))
#     if ignore_missing:
#         for i in xrange(0, len(streams)):
#             try:
#                 row[i] = streams[i].next()
#             except StopIteration:
#                 idxs[i] = -1
#     else:
#         times = map(operator.itemgetter(0), row)
        
#     while min(times) != max(times):
#         idx = times.index(min(times))
#         row[idx] = streams[idx].next()
#         times[idx] = row[idx][0]
#     return row

@data_parallel
def decimate(n):
    """Decimate a stream by yielding only 1/N records"""
    def fn(stream):
        idx = 0
        for v in stream:
            if idx % n == 0:
                yield v
            idx += 1
    return fn

@data_parallel
def subsample(windowsz, munge_times=True):
    """Subsample a stream by yielding only the first record within a window"""
    def fn(stream):
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
    return fn

@data_parallel
def count():
    def fn(stream):
        cnt = 0
        for v in stream: 
            cnt += 1
        yield (cnt,)
    return fn

@data_agg
def dfsum(streams, ignore_missing=True):
    while 1:
        row = read_aligned(streams, ignore_missing)
        if len(row) > 0:
            val = reduce(operator.__add__, map(operator.itemgetter(1), row), 0)
            yield (row[0][0], val)
        else:
            break

operators = {
    'count' : (count, []),
    'decimate' : (decimate, [int]),
    'subsample' : (subsample, [int]),
    'sum' : (dfsum, []),
    }


class TestReadAligned(unittest.TestCase):
    def makeStream(self, start, end, step=1):
        return ((x,) for x in xrange(start, end, step))
    
#     def testSimple(self):
#         streams = [self.makeStream(0, 10) for x in range(0, 5)]
#         for i in xrange(0, 10):
#             row = read_aligned(streams)
#             for j in xrange(0, 5):
#                 self.assertEquals(row[j][0], i)

    def testMissing(self):
        streams = [self.makeStream(0, 10) for x in range(0, 4)]
        streams += [self.makeStream(0, 5)]
        for i in xrange(0, 5):
            row = read_aligned(streams)
            for j in xrange(0, 5):
                self.assertEquals(row[j][0], i)

        for i in xrange(5, 10):
            row = read_aligned(streams)
            for j in xrange(0, 4):
                self.assertEquals(row[j][0], i)


if __name__ == '__main__':
    unittest.main()
#     def data(start):
#         for x in xrange(start, 1000):
#             yield (x, x)

#     streams = [data(0), data(10)]
#     op = sum(subsample(streams, 50))
#     print op

#     print map(list, op)

# #     print list(decimate(10)(data()))
# #     print list(subsample(10)(data()))
