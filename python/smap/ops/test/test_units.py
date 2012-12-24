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
import numpy as np
from twisted.trial import unittest

from smap.ops.util import StandardizeUnitsOperator

class TestUnits(unittest.TestCase):
    """Test the unit conversion operator"""

#     def test_lookup(self):
#         op = StandardizeUnitsOperator([{
#                     'uuid': 12,
#                     'Properties/UnitofMeasure': 'W'}])
#         self.assertEquals(op.find_conversion('W')[0], 'kW')
#         self.assertEquals(op.find_conversion('deg F')[0], 'C')
#         self.assertEquals(op.find_conversion('Deg F')[0], 'C')
#         self.assertEquals(op.find_conversion('lbs/hr')[0], 'lbs/hr')
#         self.assertEquals(op.find_conversion('Lbs/hour')[0], 'lbs/hr')

    def test_op(self):
        # watts
        op = StandardizeUnitsOperator([{
                    'uuid': 'caa850e0-4c67-11e2-8699-97d49b2d114e',
                    'Properties/UnitofMeasure': 'W'}])
        self.assertEquals(op([np.array([[0, 1000]])])[0][0,1], 1.0)

        # Fahrenheit
        op = StandardizeUnitsOperator([{
                    'uuid': 'caa850e0-4c67-11e2-8699-97d49b2d114e',
                    'Properties/UnitofMeasure': 'deg F'}])
        self.assertEquals(op([np.array([[0, 32]])])[0][0,1], 0)
        self.assertEquals(op([np.array([[0, 212]])])[0][0,1], 100)
