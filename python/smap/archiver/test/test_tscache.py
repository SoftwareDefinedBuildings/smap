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

