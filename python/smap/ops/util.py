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
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import copy
import operator
import datetime
import numpy as np
import pprint

from smap.core import SmapException
from smap.operators import Operator, ParallelSimpleOperator, CompositionOperator, mknull
from smap.contrib import dtutil

class StandardizeUnitsOperator(Operator):
    """Make some unit conversions"""
    operator_name = 'units'
    operator_constructors = [()]

    units = {
        'Watts' : ('kW', 0.001),
        'W' : ('kW', 0.001),
        'pounds/hour' : ('lbs/hr', 1.0),
        'Lbs/hr' : ('lbs/hr', 1.0),
        'lbs/min' : ('lbs/hr', 60),
        'lbs/hour' : ('lbs/hr', 1.0),
        'Def F' : ('F', 1.0),
        }
    name = 'standardize units'
    required_tags = set(['uuid', 'Properties/UnitofMeasure'])

    def __init__(self, inputs):
        self.factors = [1.0] * len(inputs)
        outputs = copy.deepcopy(inputs)
        for i in xrange(0, len(inputs)):
            if 'Properties/UnitofMeasure' in inputs[i] and \
                    inputs[i]['Properties/UnitofMeasure'] in self.units:
                self.factors[i] = self.units[inputs[i]['Properties/UnitofMeasure']][1]
                outputs[i]['Properties/UnitofMeasure'] = \
                    self.units[inputs[i]['Properties/UnitofMeasure']][0]
        Operator.__init__(self, inputs, outputs)

    def process(self, data):
        return map(lambda (i, x): np.dstack((x[:, 0], x[:,1] * self.factors[i]))[0],
                   enumerate(data))


class NullOperator(Operator):
    name = 'null'
    def __init__(self, inputs):
        # don't change uuids
        Operator.__init__(self, inputs, inputs)

    def process(self, inputs):
        return inputs


class PrintOperator(NullOperator):
    """N-N operator which prints all the input data
    """
    name = "print"
    operator_name = 'print'
    operator_constructors = [()]
    def process(self, inputs):
        print inputs
        return inputs

class NlOperator(ParallelSimpleOperator):
    """Append a column to all inputs with the index of each element"""
    name = 'nl'
    operator_name = 'nl'
    operator_constructors = [()]

    @staticmethod
    def base_operator(vec):
        return np.column_stack([vec, np.arange(0, len(vec))])
        
    def __init__(self, inputs):
        # don't change uuids
        ParallelSimpleOperator.__init__(self, inputs) 


class StripMetadata(Operator):
    name = "strip_metadata"
    operator_name = 'strip_metadata'
    operator_constructors = [()]

    def __init__(self, inputs):
        outputs = [{} for x in xrange(0, len(inputs))]
        for i, stream in enumerate(inputs):
            for k, v in stream.iteritems():
                if not k.startswith('Metadata/'):
                    outputs[i][k] = v
        Operator.__init__(self, inputs, outputs)

    def process(self, inputs):
        return inputs


class MissingDataOperator(ParallelSimpleOperator):
    """For pasted input data, only yield rows where more
    than ndatathresh percent of the streams have data (that is, are
    not nan).

    inputs: equal-length vectors with missing data represented by nan
    outputs: the same data, but only where sufficient streams have data
    """
    name = 'missing filter'
    operator_name = 'missing'
    operator_constructors = [(), (float,)]

    def __init__(self, inputs, ndatathresh=0.6):
        ParallelSimpleOperator.__init__(self, inputs, ndatathresh=ndatathresh)
        if ndatathresh < 0 or ndatathresh > 1:
            raise SmapException("Invalid data availability threshold: must be in [0, 1]")

    @staticmethod
    def base_operator(data, ndatathresh=0.6):
        length, width = data.shape
        width -= 1
        nancnt = np.sum(np.isnan(data[:, 1:]), axis=1)
        takerows = np.where(width - nancnt >= width * ndatathresh)
        if len(takerows[0]):
            return data[takerows]
        else:
            return mknull(width)


class MaskedDTList:
    """List which lazily performs datetime conversions, and memoizes
    the result"""
    def __init__(self, lst, tz):
        self.lst = list(lst)
        self.dts = [None] * len(lst)
        self.tz = tz
        self.conversions = 0
    
    def __getitem__(self, i):
        if self.dts[i]: 
            return self.dts[i]
        else:
            dt = datetime.datetime.fromtimestamp(self.lst[i], self.tz)
            self.dts[i] = dt
            self.conversions += 1
            return dt

    def __len__(self):
        assert len(self.lst) == len(self.dts)
        return len(self.lst)

    def extend(self, lst):
        self.lst.extend(lst)
        self.dts.extend([None] * len(lst))

    def truncate(self, i):
        self.lst = self.lst[i:]
        self.dts = self.dts[i:]

