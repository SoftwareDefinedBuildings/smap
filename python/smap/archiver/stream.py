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

import numpy as np
from twisted.internet import reactor

import smap.util as util
import smap.operators as operators
import querygen as qg

from smap.ops import installed_ops

def get_operator(name, args):
    """Look up an operator by name.  If given args, try to parse them
    using whatever initializer lists are available.

    :raises: ParseException if it can't match the operator
    """
    args, kwargs = args
    # groups = filter(lambda x: type(x) == type('') and x[0] == '$', args)
    # args = filter(lambda x: type(x) != type('') or x[0] != '$', args)
    thisop = lookup_operator_by_name(name, args[1:], kwargs)
    if util.is_string(args[0]):
        # then our input will be bound somewhere else
        return thisop
    else:
        # otherwise assume the first op is another operator, and we
        # need to compose them
        return operators.make_composition_operator([args[0], thisop])

def lookup_operator_by_name(name, args, kwargs):
    """Lookup an operator by name and return a closure which will
    instantiate the operator with the given args and kwargs"""
    if not name in installed_ops:
        raise qg.QueryException("No such operator: " + name)
    if len(args) == 0 and len(kwargs) == 0:
        # if the op doesn't take any args, just return the bare operator
        return installed_ops[name]
    else:
        for proto in installed_ops[name].operator_constructors:
            if len(proto) != len(args): continue
            try:
                alist = map(lambda (fn, a): fn(a), zip(proto, args))
                kwargs_ = kwargs
            except ValueError:
                continue

            return lambda inputs: installed_ops[name](inputs, *alist, **kwargs_)
        raise qg.QueryException("No valid constructor for operator %s: %s" % 
                                (name, str(args)))

def make_applicator(appop, group=None):
    """Make a closure that will apply the operator expresion to a
    specific set of streams and metadata."""

    def build_result((d, s)):
        obj = dict(s)
        if isinstance(d, np.ndarray):
            d[:,0] = np.int_(d[:, 0])
            d[:,0] *= 1000
            obj['Readings'] = d.tolist()
        else:
            obj['Readings'] = d
        return util.build_recursive(obj, suppress=[])

    def apply_op(data):
        opmeta = data[0][1]
        opmeta = map(lambda x: dict(util.buildkv('', x)), opmeta)
        if not len(opmeta):
            return []

        # build the operator
        if group and len(group):
            op = smap.ops.grouping.GroupByTagOperator(opmeta, appop, group[0])
        else:
            op = appop(opmeta)

        # insert the data in the right index for the operator (it
        # could come back in any order)
        opdata = [operators.null] * len(op.inputs)
        for v in data[1][1]:
            if len(v['Readings']):
                idx = op.index(v['uuid'])
                opdata[idx] = np.array(v['Readings'])
                opdata[idx][:, 0] /= 1000

        # process
        redata = op.process(opdata)

        # construct a return value with metadata and data merged
        return map(build_result, zip(redata, op.outputs))

    return apply_op    
