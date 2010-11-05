
import sys
import unittest
import time
sys.path.append('..')

import SmapPoint

class TestSmapPoint(unittest.TestCase):
    def testGetDir(self):
        p = SmapPoint.SmapPoint(None, None)
        dir = p.http_get([])
        self.assertEqual(set(p.http_get([])),
                         set(['reading', 'parameter', 'formatting', 'profile']))

    def testGetReading(self):
        now = time.time()
        p = SmapPoint.SmapPoint(None, None)
        p.add(SmapPoint.Reading(now, 12, None, None))
        reading = p.http_get(['reading'])

        self.assertEquals(reading['Reading'], 12)
        self.assertEquals(reading['Version'], 1)
        self.assertEquals(reading['ReadingTime'], now)

if __name__ == '__main__':
    import SmapHttp
    SmapHttp.smap_server_init(None)
    unittest.main()
