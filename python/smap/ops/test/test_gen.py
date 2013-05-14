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

from smap import operators, core
from smap.ops import grouping, arithmetic
from smap.ops import util as oputils
from smap.contrib import dtutil
from smap.archiver.queryparse import parse_opex

class TestParser(unittest.TestCase):
    """Test the group by time operator"""

    def test_mergedsum(self):
        q = "nansum(axis=1) < paste < swindow(first, 20)"
        op = parse_opex(q).ast
        inst = op([{'uuid' : str(uuid.uuid1()), 'Properties/Timezone': 'America/Los_Angeles'},
                   {'uuid' : str(uuid.uuid1()), 'Properties/Timezone': 'America/Los_Angeles'},
                   {'uuid' : str(uuid.uuid1()), 'Properties/Timezone': 'America/Los_Angeles'},
                   {'uuid' : str(uuid.uuid1()), 'Properties/Timezone': 'America/Los_Angeles'}])
        self.assertFalse(inst.block_streaming)
        self.assertEquals(len(inst.outputs), 1)

        for i in [0, 1, 20, 21, 40, 41, 60, 61, 100, 101, 200, 300]:
            d = [operators.null] * 4
            d[i % 20] = np.array([[i * 1000, 1]])

            out = inst(d)
            if i == 40:
                self.assertEquals(np.sum(out[0] - np.array([[0, 2]])), 0)
            elif i == 60:
                self.assertEquals(np.sum(out[0] - np.array([[20 * 1000, 2]])), 0)
            elif i == 100:
                self.assertEquals(np.sum(out[0] - np.array([[40 * 1000, 2], [60 * 1000, 2]])), 0)
