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

Implement basic passthroughs for operators from numpy to ARQ.  There
are a few operator styles; some are row-wise, some are column-wise,
and some are element wise.  This module creates classes for them which
support operation in either dimension (where possible).

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

from smap import operators
import numpy as np
from scipy import stats

def vector_operator_factory(name, op, constructors=[()], block_streaming=True):
    """Make a new vector operator class (type) from its name and operator"""
    classname = name.capitalize() + "VectorOperator"
    class Metaclass(type):
        def __new__(meta, _classname, bases, classdict):
            klass = type.__new__(meta, classname, bases, classdict)
            klass.base_operator = staticmethod(op)
            klass.name = name
            klass.operator_name = name
            klass.operator_constructors = constructors
            klass.block_streaming = block_streaming
            return klass

    class Op(operators.VectorOperator):
        __metaclass__ = Metaclass

    return Op

def _op_from_vector_ops(name, nameop, argop, constructors=[()]):
    """Generate a sMAP operator from a pair of operators which can
    work on either axis.

    Th
    """
    def _operator(data, *args, **kwargs):
        if not 'axis' in kwargs: kwargs['axis'] = 1
        if np.size(data) == 0: return operators.null
        if kwargs['axis'] == 0:
            return data[argop(data[:, 1:], *args, **kwargs)]
        elif kwargs['axis'] == 1:
            return np.dstack((data[:, 0], 
                              nameop(data[:, 1:], *args, **kwargs)))[0]
    _operator.__doc__ = nameop.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors)
    return _opclass

# arithmetic operators that have arg- versions.  using those we can
# pass along the timestamps
max = _op_from_vector_ops('max', np.max, np.argmax)
min = _op_from_vector_ops('min', np.min, np.argmin)

def _op_from_compressive_op(name, op, constructors=[()], timestamp=np.min):
    """Generate a sMAP operator from a single operator which can't
    pick a time stamp

    The input operators need to be "compressive" and only output one
    value for each input vector.  This means that they are not able to
    work in streaming mode.
    """
    def _operator(data, *args, **kwargs):
        if not 'axis' in kwargs: kwargs['axis'] = 1
        if np.size(data) == 0: return operators.null
        if kwargs['axis'] == 0:
            v = np.hstack(([timestamp(data[:, 0])], 
                           op(data[:, 1:], *args, **kwargs)))
            v = v.reshape((1, len(v)))
            return v
        elif kwargs['axis'] == 1:
            return np.dstack((data[:, 0], op(data[:, 1:], *args, **kwargs)))[0]
    _operator.__doc__ = op.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors)
    _opclass.type = 'compressive'
    return _opclass

# for most operators the timestamps aren't super meaningful so doing
# something like taking the first one is sensible for column-wise
# operator.
# percentile = _op_from_compressive_op('percentile', np.percentile, [(float,)])
median = _op_from_compressive_op('median', np.median)
mean = _op_from_compressive_op('mean', np.mean)
sum = _op_from_compressive_op('sum', np.sum)
nansum = _op_from_compressive_op('nansum', np.nansum)
var = _op_from_compressive_op('var', np.var)
std = _op_from_compressive_op('std', np.std)
prod = _op_from_compressive_op('prod', np.prod)

nanmean = _op_from_compressive_op('nanmean', stats.nanmean)

# ufuncs operate element-by-element on arrays
#  these operators trivially support streaming
def _op_from_ufunc(name, op, constructors=[()]):
    def _operator(data, *args, **kwargs):
        if 'axis' in kwargs:
            del kwargs['axis']
        d = op(data[:, 1:], *args, **kwargs)
        return np.hstack((data[:, 0].reshape((d.shape[0], 1)), d))
    _operator.__doc__ = op.__doc__
    _opclass = vector_operator_factory(name, _operator, constructors,
                                       block_streaming=False)
    _opclass.type = 'ufunc'
    return _opclass

add = _op_from_ufunc('add', np.add, [(float,)])
multiply = _op_from_ufunc('multiply', np.multiply, [(float,)])
log = _op_from_ufunc('log', np.log)
log10 = _op_from_ufunc('log10', np.log10)
sqrt = _op_from_ufunc('sqrt', np.sqrt)
power = _op_from_ufunc('power', np.power, [(float,)])
exp = _op_from_ufunc('exp', np.exp)
absolute = _op_from_ufunc('absolute', np.absolute)
rint = _op_from_ufunc('rint', np.rint)
ceil = _op_from_ufunc('ceil', np.ceil)
floor = _op_from_ufunc('floor', np.floor)
trunc = _op_from_ufunc('trunc', np.trunc)
around = _op_from_ufunc('around', np.around)
clip = _op_from_ufunc('clip', np.clip, [(float, float)])

isnan = _op_from_ufunc('isnan', np.isnan)
greater = _op_from_ufunc('greater', np.greater, [(int,),(float,),])
greater_equal = _op_from_ufunc('greater_equal', np.greater_equal, [(int,),(float,)])
less = _op_from_ufunc('less', np.less, [(float,)])
less_equal = _op_from_ufunc('less_equal', np.less_equal, [(int,),(float,)])
equal = _op_from_ufunc('equal', np.equal, [(int,),(float,)])
not_equal = _op_from_ufunc('not_equal', np.not_equal, [(int,),(float,)])

def _diff(data, axis=1):
    """Compute discrete differences in either axis"""
    rdata = np.diff(data[:, 1:], axis)
    return np.column_stack((data[:, 0], rdata))
diff = vector_operator_factory('diff', _diff)

def _first(data, axis=0):
    """Return the first column or the first row of data.
    """
    if axis == 1:
        return data[:, 0:2]
    elif axis == 0:
        rv = data[0, :] if np.size(data) else operators.null
        if len(rv.shape) != 2:
            rv = np.reshape(rv, (1, rv.shape[0]))
        return rv
first = vector_operator_factory('first', _first, block_streaming=False)

def _count(data, axis=0):
    """Return the number of rows or columns of data"""
    shape = np.shape(data)
    if axis == 0: 
        return shape[0]
    elif axis == 1: 
        return np.ones(shape[0]) * shape[1]
count = _op_from_compressive_op('count', _count)

def _product(data, axis=0):
    if axis == 0:
        return reduce(np.multiply, data[1:], data[0, :])
    if axis == 1:
        return reduce(np.multiply, data.T[1:], data[:, 0])
product = _op_from_compressive_op('product', _product)
