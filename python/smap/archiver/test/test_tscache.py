
from smap.archiver.tscache import TimeseriesCache
from twisted.trial import unittest

import numpy as np

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

