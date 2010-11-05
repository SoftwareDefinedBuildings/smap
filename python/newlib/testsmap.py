
import urllib
import json
import unittest
import sys
import httplib
import urlparse

TIME_UNITS = ["microsecond",
                 "millisecond",
                 "second",
                 "minute",
                 "hour",
                 "day",
                 "week",
                 "fortnight",
                 "month",
                 "year",
                 "decade"]
M_TYPES = ["electric",
           "gas",
           "fan speed",
           "water",
           "wind",
           "light",
           "air",
           "time",
           "soil",
           "other"]

M_UNITS = ["m", "Kg", "s", "A", "cd", "mol", "cd/m3", "lm", "lx", "kW", 
           "kVAR", "kVA", "kWh", "kVARh", "kVAh", "V", "PF", "Hz", "l", 
           "m3", "rad", "deg", "sr", "kg/m3", "pH","N","Pa", "rh", "Nm", 
           "Wb", "H", "C", "F", "K", "Q", "m/s", "pct" ]

class SmapTestCase(unittest.TestCase):
    def setUp(self):
        self.url = "http://localhost:8080"

    def _get(self, url):
        fp = urllib.urlopen(url)
        obj = json.load(fp)
        return obj

    def testRoot(self):
        self.assertEquals(set(self._get(self.url)), set(['reporting','data']))

    def testReports(self):
        self.assertEquals(set(self._get(self.url + 'reporting')), set(['reports','create']))

    def testData(self):
        """Check that we get the same answer using the */* syntax as
        we get by reading the directory listing
        """
        channels = dict([(x,None) for x in self._get(self.url + "data")])
        for c in channels:
            channels[c] = dict([(x,None) for x in self._get(self.url + "data/" + c)])

            for p in channels[c].keys():
                channels[c][p] = self._get(self.url + '/data/' + c + '/' + p + '/reading')
        full_channels = self._get(self.url + 'data/*/*/reading')
        self.assertEquals(channels, full_channels)

    def testReadings(self):
        readings = self._get(self.url + 'data/*/*/reading')
        for c in readings.iterkeys():
            for p in readings[c].iterkeys():
                self.assertTrue(readings[c][p].has_key('Reading'))
                self.assertTrue(readings[c][p].has_key('ReadingTime'))

    def testFormatting(self):
        fmt = self._get(self.url + 'data/*/*/formatting')
        for c in fmt.iterkeys():
            for p in fmt[c].iterkeys():
                self.assertTrue(fmt[c][p].has_key('UnitofTime'))
                self.assertTrue(fmt[c][p].has_key('UnitofMeasure'))
                self.assertTrue(fmt[c][p].has_key('MeterType'))
                self.assertTrue(fmt[c][p].has_key('ChannelType'))

                self.assertTrue(fmt[c][p]['UnitofTime'] in TIME_UNITS)
                self.assertTrue(fmt[c][p]['UnitofMeasure'] in M_UNITS)
                self.assertTrue(fmt[c][p]['MeterType'] in M_TYPES)
                self.assertTrue(fmt[c][p]['ChannelType'] in ['sensor', 'meter'])

    def testParameter(self):
        param = self._get(self.url + 'data/*/*/parameter')
        for c in param.iterkeys():
            for p in param[c].iterkeys():
                self.assertTrue(param[c][p].has_key('SamplingPeriod'))
                self.assertTrue(param[c][p].has_key('IntervalSinceLastReading'))
                self.assertTrue(param[c][p].has_key('UnitofTime'))

                self.assertTrue(param[c][p]['UnitofTime'] in TIME_UNITS)

    def testReportCreateDelete(self):
        start_reports = self._get(self.url + '/reporting/reports')

        # create a new report object by POSTing an object to the server
        create_object = {
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/meter/reporting/create"},
            "Period"  : 0,
            "ReportResource" : '/data/*/*/reading',
            "ReportDeliveryLocation" : 'http://localhost/',
            }

        location = urlparse.urlparse(self.url)
        headers = {"Content-type" : "application/json"}
        conn = httplib.HTTPConnection(location.netloc)
        conn.request("POST", 
                     location.path + '/reporting/create',
                     json.dumps(create_object),
                     headers)
        response = conn.getresponse()
        reply = json.loads(response.read())
        conn.close()

        # check that we get the right code back
        self.assertEquals(response.status, httplib.OK)
        self.assertEquals(len(reply), 1)
        self.assertEquals(len(reply[0]), 8)

        # now delete it
        conn.request("DELETE",
                     location.path + '/reporting/reports/' + reply[0],
                     None, {})
        response = conn.getresponse()
        conn.close()
        
        self.assertEquals(response.status, httplib.OK)

        # check it's actually gone and we didn't delete anything else
        end_reports = self._get(self.url + '/reporting/reports')
        self.assertEquals(set(start_reports), set(end_reports))

if __name__ == '__main__':
    unittest.main()
