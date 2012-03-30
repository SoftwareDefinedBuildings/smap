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
        
        
