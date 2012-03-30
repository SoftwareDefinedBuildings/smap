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

from twisted.trial import unittest

import sys
sys.path.append('..')

from uuid import UUID
import uuid
import shutil

from smap import reporting, util


class TestDataBuffer(unittest.TestCase):
    TEST_DIR = "test_dir"
    def setUp(self):
        try:
            shutil.rmtree(self.TEST_DIR)
        except OSError:
            pass
    
    def test_onestream(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(self.TEST_DIR)

        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv = d.read()
        self.assertEqual(len(rv), 1)
        self.assertTrue('/test' in rv)
        val = rv['/test']
        self.assertTrue('uuid' in val)
        self.assertTrue('Readings' in val)
        self.assertTrue(val['uuid'] == u)
        self.assertEqual(len(val['Readings']), 20)
        for i in xrange(0, 20):
            self.assertEqual(val['Readings'][i]['ReadingTime'], i)
            self.assertEqual(val['Readings'][i]['Reading'], i)
        del d

    def test_partialread(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(self.TEST_DIR)

        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        # make sure we don't mutate the object while doing this...
        rv = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 20)
        rv = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 20)
        del d

    def test_maxsize(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(10)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        rv = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        for i in xrange(10, 20):
            self.assertEqual(rv['/test']['Readings'][i-10]['ReadingTime'], i)
            self.assertEqual(rv['/test']['Readings'][i-10]['Reading'], i)
        del d
    test_maxsize.skip = 'out of date'

    def test_truncate(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(self.TEST_DIR)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv = d.read()
        print len(d)
        self.assertEqual(len(rv['/test']['Readings']), 20)
        d.truncate(tspec)
        self.assertEqual(len(d), 19)
        del d
    test_truncate.skip = 'out of date'

    def test_metadata_split(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(self.TEST_DIR)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        d.add('/test', {'uuid': u, 'Metadata' : {'Extra': {'foo': 'bar'} } })
        rv = d.read()
        d.truncate()
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv = d.read()

    def test_truncate_adds(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(self.TEST_DIR)
        
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        rv = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        self.assertEqual(rv['/test']['Readings'][0]['Reading'], 0)

        for i in xrange(20, 30):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        rv = d.read()  # should be the next 10 since we overwrite
        self.assertEqual(len(rv['/test']['Readings']), 10)
        self.assertEqual(rv['/test']['Readings'][0]['Reading'], 10)

        d.truncate(tspec) # this doesn't do anything b/c we overwrote it in the circular buffer
        rv, tspec = d.read()  # should be the next 10
        self.assertEqual(len(rv['/test']['Readings']), 10)
        self.assertEqual(rv['/test']['Readings'][0]['Reading'], 10)

        d.truncate(tspec)
        rv, tspec = d.read() # read past the end
        self.assertEqual(len(rv['/test']['Readings']), 10)
        self.assertEqual(rv['/test']['Readings'][0]['Reading'], 20)

        d.truncate(tspec)
        rv, tspec = d.read() # read past the end
        self.assertEqual(len(rv), 0)
        del d
    test_truncate_adds.skip = 'out of date'

class TestReportingCopy(unittest.TestCase):
    def test_simple(self):
        obj = {'uuid': UUID('6deb57a0-183d-54dc-bbbf-b381e5324068'), 
               'Readings': [{'Reading': 0, 'ReadingTime': 1310758135000}]}
        copy = reporting.reporting_copy(obj)
        self.assertEqual(obj, copy)
        self.assertNotEqual(id(obj), id(copy))
