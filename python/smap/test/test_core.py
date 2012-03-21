
import uuid
from twisted.trial import unittest

from smap import core

class TestTimeseries(unittest.TestCase):
    def test_init(self):
        # constructor should die without the right args
        self.assertRaises(core.SmapSchemaException, core.Timeseries, {}, '')
        self.assertRaises(core.SmapSchemaException, core.Timeseries, {
                'uuid': None}, '')
        self.assertRaises(core.SmapSchemaException, core.Timeseries, {
                'uuid': None, 'Readings': None}, '')
        self.assertRaises(core.SmapSchemaException, core.Timeseries, 'foo', 'kW')


    def test_invalid_attr(self):
        id = str(uuid.uuid1())
        ts = core.Timeseries(id, 'kW')
        self.assertRaises(KeyError, ts.__setitem__, 'foo', 'bar')
        self.assertRaises(core.SmapSchemaException, ts.__setitem__, 
                          'Properties', '10')
        self.assertRaises(core.SmapSchemaException, ts.__setitem__,
                          'Description', 10)

    def test_set_metadata(self):
        id = str(uuid.uuid1())
        ts = core.Timeseries(id, 'kW')
        self.assertRaises(KeyError, ts.__getitem__, 'Metadata')
        test_1 = {
            'Metadata' : {
                'Extra' : {
                    'Test' : 'Foo'
                    }
                }
            }
        ts.set_metadata(test_1)
        self.assertEqual(ts['Metadata'], test_1['Metadata'])

        test_1 = test_1['Metadata']
        test_1['Extra']['Test'] = 'Bar'
        ts.set_metadata(test_1)
        self.assertEqual(ts['Metadata'], test_1)
        
        
