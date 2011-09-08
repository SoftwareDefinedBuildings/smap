
import sys
sys.path.append('..')

import uuid
import unittest

import reporting
import util

class TestDataBuffer(unittest.TestCase):
    def test_onestream(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(20)

        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv, _ = d.read()
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
        d = reporting.DataBuffer(20)

        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        # make sure we don't mutate the object while doing this...
        rv, _ = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 20)
        rv, _ = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 20)
        del d

    def test_maxsize(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(10)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv, _ = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        rv, _ = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        for i in xrange(10, 20):
            self.assertEqual(rv['/test']['Readings'][i-10]['ReadingTime'], i)
            self.assertEqual(rv['/test']['Readings'][i-10]['Reading'], i)
        del d

    def test_truncate(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(20)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv, tspec = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 20)
        d.truncate(tspec)
        self.assertEqual(len(d), 0)
        del d

    def test_metadata_split(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(20)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        d.add('/test', {'uuid': u, 'Metadata' : {'Extra': {'foo': 'bar'} } })
        rv, tspec = d.read()
        print rv
        d.truncate(tspec)
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})
        rv, tspec = d.read()
        print rv

    def test_truncate_adds(self):
        u = uuid.uuid1()
        d = reporting.DataBuffer(20)
        
        for i in xrange(0, 20):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        rv, tspec = d.read()
        self.assertEqual(len(rv['/test']['Readings']), 10)
        self.assertEqual(rv['/test']['Readings'][0]['Reading'], 0)

        for i in xrange(20, 30):
            d.add('/test', {'uuid': u, 'Readings' : [{'ReadingTime' : i, 'Reading': i}]})

        rv, _ = d.read()  # should be the next 10 since we overwrite
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

from uuid import UUID

class TestReportingCopy(unittest.TestCase):
    def test_simple(self):
        obj = {'uuid': UUID('6deb57a0-183d-54dc-bbbf-b381e5324068'), 'Readings': [{'Reading': 0, 'ReadingTime': 1310758135000}]}
        self.assertEqual(obj, reporting.reporting_copy(obj))

class TestPickle(unittest.TestCase):
    def test_simple(self):
        db = reporting.DataBuffer(10)
        util.pickle_dump('test', db)

        ri = reporting.ReportInstance(10, {
                'ReportDeliveryLocation' : 'http://foo'
                })
        util.pickle_dump('test', ri)

        uu = uuid.uuid1()
        util.pickle_dump('test', uu)


if __name__ == '__main__':
    unittest.main()
