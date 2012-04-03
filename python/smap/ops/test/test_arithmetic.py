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

from smap.ops.test.test_group import make_input_meta, make_test_data
from smap import operators
from smap.ops import arithmetic

class TestArithmetic(unittest.TestCase):
    def setUp(self):
        self.udata = make_test_data(5)
        self.jdata = operators.transpose_streams(self.udata)

    def test_max(self):
        # test axis 0
        for i in xrange(0, 5):
            rv = arithmetic.max.base_operator(self.udata[i], axis=0)
            self.assertEquals(np.sum(rv - self.udata[i][-1, :]), 0)

        # test axis 1
        rv = arithmetic.max.base_operator(self.jdata)
        self.assertEquals(np.sum(rv[:, 0] - self.jdata[:, 0]), 0)
        self.assertEquals(np.sum(rv[:, 1] - self.jdata[:, -1]), 0)
        

    def test_min(self):
        # test axis 0
        for i in xrange(0, 5):
            rv = arithmetic.min.base_operator(self.udata[i], axis=0)
            self.assertEquals(np.sum(rv - self.udata[i][0, :]), 0)

        # test axis 1
        rv = arithmetic.min.base_operator(self.jdata)
        self.assertEquals(np.sum(rv[:, 0] - self.jdata[:, 0]), 0)
        self.assertEquals(np.sum(rv[:, 1] - self.jdata[:, 1]), 0)
        
    def test_median(self):
        rv = arithmetic.median.base_operator(self.jdata, axis=1)
        self.assertEquals(np.sum(rv[:, 0] - self.jdata[:, 0]), 0)
        self.assertEquals(np.sum(rv[:, 1] - np.median(self.jdata[:, 1:], axis=1)), 0)

        for i in xrange(0, 5):
            rv = arithmetic.median.base_operator(self.udata[i], axis=0)
            self.assertEquals(rv[0][0], 0)
            self.assertEquals(rv[0][1], np.median(self.udata[i][:, 1]))

    def test_first(self):
        for i in xrange(0, 5):
            rv = arithmetic._first(self.udata[i], axis=1)
            self.assertEquals(rv[0][0], 0)
            self.assertEquals(rv[0][1], 0)

        rv = arithmetic._first(self.jdata, axis=0)
        self.assertEquals(np.sum(rv - self.jdata[0, :]), 0)

        rv = arithmetic._first(operators.null, axis=0)
        self.assertEquals(rv.size, operators.null.size)
        rv = arithmetic._first(operators.null, axis=1)
        self.assertEquals(rv.size, operators.null.size)

    def test_count(self):
        rv = arithmetic.count.base_operator(self.jdata, axis=0)
        self.assertEquals(np.sum(rv), 20)

        rv = arithmetic.count.base_operator(self.jdata, axis=1)
        self.assertEquals(np.sum(rv[:, 0] - self.jdata[:, 0]), 0)
        self.assertEquals(np.sum(rv[:, 1]), 5 * 20)

    def test_sum(self):
        rv = arithmetic.sum.base_operator(self.jdata, axis=0)
        self.assertEquals(rv.shape, (1, 6))
