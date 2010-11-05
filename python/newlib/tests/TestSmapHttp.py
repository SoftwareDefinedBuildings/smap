
import sys
import unittest
import urlparse
import time
sys.path.append('..')

import SmapPoint
import SmapHttp

class RecursiveGetTestCase(unittest.TestCase):
    resource = urlparse.urlsplit("http://smap/data/0/")
    rr = urlparse.urlsplit("http://smap/data/0/reading")
    rrs = urlparse.urlsplit("http://smap/data/*/reading")
    top = urlparse.urlsplit("http://smap/")

    def test404(self):
        self.assertRaises(SmapHttp.SmapHttpException,
                          lambda: SmapHttp.recursive_get(self.resource, {}))
        
    def testGetTopDir(self):
        p = SmapPoint.SmapPoint(None, None)
        dict_heir = {'data': {'0' : p}}
        self.assertEqual(['data'], SmapHttp.recursive_get(self.top, dict_heir))

    def testGetDir(self):
        p = SmapPoint.SmapPoint(None, None)
        dir = p.http_get([])
        dict_heir = {'data': {'0' : p}}
        self.assertEqual(dir, SmapHttp.recursive_get(self.resource, dict_heir))

    def testGetReading(self):
        p = SmapPoint.SmapPoint(None, None)
        p.add(SmapPoint.Reading(time.time(), 12, None, None))
        dict_heir = {'data': {'0' : p}}
        self.assertEqual(p.http_get(['reading']),
                         SmapHttp.recursive_get(self.rr, dict_heir))

    def testGetReadingStar(self):
        p = SmapPoint.SmapPoint(None, None)
        p.add(SmapPoint.Reading(time.time(), 12, None, None))
        dict_heir = {'data': {'0' : p}}
        self.assertEqual({'0' : p.http_get(['reading'])},
                         SmapHttp.recursive_get(self.rrs, dict_heir))


if __name__ == '__main__':
    SmapHttp.smap_server_init(None)
    unittest.main()
