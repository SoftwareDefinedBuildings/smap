
from smap.drivers.sumr import *
from twisted.trial import unittest

import numpy as np

class JoinedMeanTestCase(unittest.TestCase):
    """Test the moving average operator"""

    def test_bulk(self):
        data = np.ones((15, 2))
        for i in xrange(0, 15):
            data[i, 0] = i
            data[i, 1] = i
        rv, state = joinedma(data, lag=10)
        self.assertEqual(len(rv), 6)
        self.assertEqual(state['lag'], 10)
        self.assertEqual(len(state['hist']), 9)

    def test_incremental(self):
        s = {'lag': 10}
        for i in xrange(0, 15):
            rv, s = joinedma(np.array([[i, i]]), **s)
            if i < 9:
                self.assertEqual(len(rv), 0)
                self.assertEqual(len(s['hist']), i+1)
            else:
                self.assertEqual(len(rv), 1)
                self.assertEqual(rv[0][0], i)
                self.assertEqual(len(s['hist']), 9)
