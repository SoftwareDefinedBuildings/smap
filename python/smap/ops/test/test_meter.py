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

import numpy as np
from twisted.trial import unittest

from smap.ops.meter import _meter

class TestMeter(unittest.TestCase):
    def test_increasing(self):
        d = np.ones(20)
        for i in xrange(0, 20):
            d[i] = i
        rv = _meter(d, 0)
        self.assertEquals(rv, 19)

    def test_one_reset(self):
        d = np.ones(20)
        for i in xrange(0, 20):
            if i < 10: d[i] = i
            else: d[i] = i - 10
        rv = _meter(d, 0)
        self.assertEquals(rv, 18)

    def test_reset_before(self):
        d = np.ones(20)
        for i in xrange(0, 20):
            d[i] = i
        d[-1] = 3
        rv = _meter(d, 0)
        self.assertEquals(rv, 21)

    def test_reset_first(self):
        d = np.ones(20)
        for i in xrange(1, 20):
            d[i] = i
        d[0] = 10
        rv = _meter(d, 0)
        self.assertEquals(rv, 29)        

    def test_decreasing_simple(self):
        d = np.array([3, 2, 1])
        rv = _meter(d, 0)
        self.assertEquals(rv, np.sum(d))

    def test_decreasing(self):
        d = np.ones(20)
        for i in xrange(0, 20):
            d[i] = 20 - i
        rv = _meter(d, reset_threshold=0)
        self.assertEquals(rv, np.sum(d))

    def test_starting_offset(self):
        d = np.ones(20)
        for i in xrange(0, 20):
            d[i] = i + 10
        rv = _meter(d, reset_threshold=0)
        self.assertEquals(rv, 19)

