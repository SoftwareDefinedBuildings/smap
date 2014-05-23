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
import traceback
import sys
import re

from smap import operators, util
from smap.core import SmapException
from smap.operators import Operator, ParallelSimpleOperator, CompositionOperator, mknull
from smap.contrib import dtutil
from smap.ops.arithmetic import _op_from_ufunc

class StandardizeUnitsOperator(Operator):
    """Make some unit conversions"""
    operator_name = 'units'
    operator_constructors = [(),
                             (lambda x: x, str, str)]

    units = {
        re.compile('W(atts)?') : ('kW', 0.001),
        'Kilowatts' : ('kW', 1.0),
        re.compile('[Hh](orse)?[Pp](ower)?') : ('kW', 0.7457),
        'pounds/hour' : ('lbs/hr', 1.0),
        re.compile('[Ll]bs/h(ou)?r') : ('lbs/hr', 1.0),
        'lbs/min' : ('lbs/hr', 60),
        re.compile('([Dd]eg F)|F') : ('C', _op_from_ufunc('C-F', lambda v: ((v - 32.) * 5) / 9.)),
        }
    name = 'units'
    required_tags = set(['uuid', 'Properties/UnitofMeasure'])

    def find_conversion(self, stream):
        unit = stream['Properties/UnitofMeasure']
        if self.oldname == unit:
            return (self.newname, self.extra_op)
        for pat, converter in StandardizeUnitsOperator.units.iteritems():
            if util.is_string(pat):
                if unit == pat: return converter
            elif pat.match(unit):
                return converter
        return (unit, 1)

    def __init__(self, inputs, *args, **kwargs):

        # create a new converter from an operator
        if len(args) == 3:
            self.extra_op, self.oldname, self.newname = args
        else:
            self.extra_op, self.oldname, self.newname = None, None, None

        self.converters = [lambda x: x] * len(inputs)
        outputs = copy.deepcopy(inputs)
        for i in xrange(0, len(inputs)):
            if 'Properties/UnitofMeasure' in inputs[i]:
                unit, converter = self.find_conversion(inputs[i])

                # make a closure with the converter
                def make_converter():
                    _converter = converter
                    if callable(_converter):
                        return _converter([inputs[i]])
                    else: 
                        return lambda x: np.dstack((x[0][:, 0], _converter * (x[0][:,1])))

                self.converters[i] = make_converter()
                outputs[i]['Properties/UnitofMeasure'] = unit
        Operator.__init__(self, inputs, outputs)

    def process(self, data):
        return util.flatten(map(lambda (c, d): c([d]), zip(self.converters, data)))


class NullOperator(Operator):
    name = 'null'
    operator_name = 'null'
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

class SnapOperator(ParallelSimpleOperator):
    """Snap the timestamps of all readings to the nearest multiple of
    the given period (kwarg). 
    """
    name = 'snap'
    operator_name = 'snap'
    operator_constructors = [()]

    @staticmethod
    def base_operator(vec, period=3600):
        vec = np.copy(vec)
        vec[:, 0] -= np.mod(vec[:, 0], period)
        return vec

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
    """Remove all tags from the output set of streams.

    This applies only to tags starting with "Metadata/"; Properties,
    Readings, and uuid are unchanged.  This operation also does not
    mutate the stream ids.
    """
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

class SetKeyOperator(Operator):
    """Sets a key on all output streams

    For instance, adding a:

      set_key("Metadata/Extra/Name", "Foo")

    To the operator pipeline will set the Metadata/Extra/Name tag to
    "Foo" on all input streams.
    """
    name = 'set_key'
    operator_name = 'set_key'
    operator_constructors = [(str, str)]

    def __init__(self, inputs, key, value):
        # don't change uuids
        outputs = copy.deepcopy(inputs)
        for o in outputs:
            o[key] = value
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

    def __init__(self, inputs, ndatathresh=0.6, invert=False):
        ParallelSimpleOperator.__init__(self, inputs, 
                                        ndatathresh=ndatathresh,
                                        invert=invert)
        if ndatathresh < 0 or ndatathresh > 1:
            raise SmapException("Invalid data availability threshold: must be in [0, 1]")

    @staticmethod
    def base_operator(data, ndatathresh=0.6, invert=False):
        length, width = data.shape
        width -= 1
        nancnt = np.sum(np.isnan(data[:, 1:]), axis=1)
        print "invert?", invert
        if not invert:
            takerows = np.where(width - nancnt >= width * ndatathresh)
        else:
            takerows = np.where(width - nancnt <= width * ndatathresh)
            
        if len(takerows[0]):
            return data[takerows[0], :]
        else:
            return mknull(width)

def make_colspec(cols):
    return map(int, cols.split(','))


class CopyOperator(ParallelSimpleOperator):
    name = "copy"
    operator_name = "copy"
    operator_constructors = [(), (str,)]

    def __init__(self, inputs, cols=""):
        cols = make_colspec(cols)
        return ParallelSimpleOperator.__init__(self, inputs, cols=cols)

    @staticmethod
    def base_operator(data, cols=""):
        return np.column_stack([data] + map(lambda i: data[:, i], cols))

class IndexOperator(ParallelSimpleOperator):
    name = "index"
    operator_name = "index"
    operator_constructors = [(), (str,)]

    def __init__(self, inputs, cols=""):
        cols = make_colspec(cols)
        return ParallelSimpleOperator.__init__(self, inputs, cols=cols)

    @staticmethod
    def base_operator(data, cols=""):        
        return np.column_stack([data[:, 0]] + map(lambda i: data[:, i], cols))

class AddColumnOperator(Operator):
    name = 'addcol'
    operator_name = 'catcol'
    operator_constructors = [(str, lambda x: x)]
    def __init__(self, inputs, cols="1", operator=None):

        self.cols = make_colspec(cols)
        self.ops = map(lambda x: operator([x]), inputs)
        self.name = 'catcol(%s, %s)' % (','.join(map(str, self.cols)), 
                                        str(self.ops[0]))
        # print self.cols, self.ops
        Operator.__init__(self, inputs, operators.OP_N_TO_N)

    def process(self, data):
        rv = []
        for i, d in enumerate(data):
            input_data = np.column_stack((d[:, 0], d[:, self.cols]))
            newcols = self.ops[i]([input_data])
            assert len(newcols) == 1
            rv.append(np.column_stack((d, newcols[0][:, 1:])))
        return rv


class RenameOperator(Operator):
    name = 'rename'
    operator_name = 'rename'
    operator_constructors = [(str, str)]

    def __init__(self, inputs, tag, newname):
        self.name = 'rename(%s, %s)' % (tag, newname)
        output = copy.deepcopy(inputs)
        for s in output:
            if tag in s:
                s[newname] = s[tag]
                del s[tag]
        Operator.__init__(self, inputs, output)

    def process(self, data):
        return data

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
        self.conversions = 0
        self.lst = self.lst[i:]
        self.dts = self.dts[i:]

    def __iter__(self):
        for i in xrange(0, len(self)):
            yield self.__getitem__(i)

