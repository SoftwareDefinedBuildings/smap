
import os
import logging
import shelve
import pickle
import numpy as np
import unittest

CACHEDIR='.cache'

def from_key(s):
    x = s.split('-')
    return (int(x[0]), int(x[1]))

def filter_data(range, data):
    idx = (data[:,0] >= range[0]) & (data[:,0] <= range[1])
    return data[np.nonzero(idx)]

class TimeseriesCache:
    """Cache of timeseries data.

    A time series cache allows clients to store on disk a single
    time-series (a sequence of time, value tuples) and read back
    ranges.  If only part of the data is available, the cache will
    return the segments so the application can query the data store
    for the remaining data, and presumably insert it into the cache.
    """
    def __init__(self, identifier, ondisk=True):
        self.log = logging.getLogger("TimeseriesCache")
        if ondisk:
            try:
                os.makedirs(CACHEDIR)
            except OSError:
                pass
            self.cache = shelve.open(os.path.join(CACHEDIR, identifier), 
                                     protocol=2)
        else:
            self.log.info("Using non-persistant cache")
            self.cache = {}

    def close(self):
        self.cache.close()

    def clear(self):
        self.cache.clear()
        self.cache.sync()

    def insert(self, substream, start, end, data):
        """Insert new data into the cache
        """
        key = "%i-%i" % (start, end)
        substream = str(substream)
        if len(data) == 0: return
        if not self.cache.has_key(substream):
            self.cache[substream] = {key:  data}
        else:
            # do this due to copy issues with shelve
            ssdata = self.cache[substream]
            ssdata[key] = data
            self.cache[substream] = ssdata
        self.cache.sync()

    def set_meta(self, meta):
        self.cache['meta'] = meta
        self.cache.sync()

    def get_meta(self):
        return self.cache.get('meta')

    def read(self, substream, start, end):
        """Read back fragments of data from the cache in the range [start, end] (inclusive)
        """
        pointer = 0
        substream = str(substream)
        rv = []
        if not substream in self.cache:
            return []

        for k in sorted(self.cache[substream].keys(), key=lambda k: from_key(k)[0]):
            (s,e) = from_key(k)
            key = None
            if s <= start and e > start:
                key = (max(pointer, start), min(e, end))
            elif s >= start and s < end:
                key = (max(pointer, s), min(e, end))

            if key != None and key[1] > pointer:
                pointer = key[1]
                rv.append((key, filter_data(key, self.cache[substream][k])))
        return rv

class TimeseriesTest(unittest.TestCase):
    SS = 0

    def setUp(self):
        c = TimeseriesCache('test')
        c.insert(self.SS, 0, 10, np.array(zip(range(0, 10), range(0,10))))
        c.insert(self.SS, 20, 30, np.array(zip(range(20, 30), range(20,30))))
        c.insert(self.SS, 30, 40, np.array(zip(range(30, 40), range(30,40))))
        c.close()

    def tearDone(self):
        c = TimeseriesCache('test')
        c.clear()
        c.close()

    def testInserted(self):
        c = TimeseriesCache('test')
        self.assertTrue(c.cache.has_key('0'))
        self.assertTrue(c.cache['0'].has_key('0-10'))
        self.assertTrue(c.cache['0'].has_key('20-30'))

    def testSave(self):
        c = TimeseriesCache('test')
        c.set_meta({'test': True})
        c.close()
        r = TimeseriesCache('test')
        self.assertEqual(r.get_meta(), {'test' : True})
        r.close()

    def testSimpleRead(self):
        c = TimeseriesCache('test')
        rv = c.read(self.SS, 0, 1)
        self.assertEqual(len(rv),1)
        rv = rv[0]
        self.assertEqual(rv[0], (0,1))
        self.assertEqual(len(rv[1]), 2)
        c.close()
        
    def testPartialRead(self):
        c = TimeseriesCache('test')
        rv = c.read(self.SS, 5, 15)
        self.assertEqual(len(rv), 1)
        rv = rv[0]
        self.assertEqual(rv[0], (5, 10))
        self.assertEqual(len(rv[1]), 5)
        self.assertEqual(rv[1][0,0], 5)
        self.assertEqual(rv[1][-1,0], 9)
        c.close()

    def testDoubleSplitRead(self):
        c = TimeseriesCache('test')
        rv = c.read(self.SS, 5, 25)
        self.assertEqual(len(rv), 2)
        # first frag
        self.assertEqual(rv[0][0], (5,10))
        self.assertEqual(rv[0][1][0,0], 5)
        self.assertEqual(rv[0][1][-1,0], 9)

        self.assertEqual(rv[1][0], (20,25))
        self.assertEqual(rv[1][1][0,0], 20)
        self.assertEqual(rv[1][1][-1,0], 25)
        c.close()

    def testCoveringRead(self):
        c = TimeseriesCache('test')
        rv = c.read(self.SS, 5, 30)
        self.assertEqual(len(rv), 2)
        self.assertEqual(rv[0][0], (5,10))
        self.assertEqual(rv[0][1][0,0], 5)
        self.assertEqual(rv[0][1][-1,0], 9)

        self.assertEqual(rv[1][0], (20,30))
        self.assertEqual(rv[1][1][0,0], 20)
        self.assertEqual(rv[1][1][-1,0], 29)
        c.close()

    def testNeighboringRead(self):
        c = TimeseriesCache('test')
        rv = c.read(self.SS, 15, 44)
        c.close()

    def testNoSS(self):
        c = TimeseriesCache('test')
        self.assertEqual(c.read(self.SS+1, 0, 10), [])
        c.close()

if __name__ == '__main__':
    unittest.main()
