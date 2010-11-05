
import sys
import unittest
import urlparse
import time
sys.path.append('..')

import SmapInstance
import SmapPoint
import SmapHttp

class SmapInstanceTestCase(unittest.TestCase):
    def testTopDir(self):
        resource = urlparse.urlsplit('http://test/')
        inst = SmapInstance.SmapInstance({})
        self.assertEqual(set(SmapHttp.recursive_get(resource, inst)),
                         set(['data', 'reporting']))

    def testReading(self):
        now = time.time()
        p = SmapPoint.SmapPoint(None, None)
        p.add(SmapPoint.Reading(now, 12, None, None))
        inst = SmapInstance.SmapInstance({'0' : p})
        resource = urlparse.urlsplit('http://test/data/0/reading')
        self.assertEqual(SmapHttp.recursive_get(resource, inst),
                         p.http_get(['reading']))

if __name__ == '__main__':
    SmapHttp.smap_server_init(None)
    unittest.main()
