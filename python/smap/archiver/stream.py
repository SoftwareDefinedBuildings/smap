
import inspect
import numpy as np

import smap.util as util
import smap.operators as operators
import querygen as qg

import smap.operators
import smap.drivers.sumr
import smap.drivers.resamplr

operator_modules = [
    smap.operators,
    smap.drivers.sumr,
    smap.drivers.resamplr,
    ]

installed_ops = {}

def discover():
    for m in operator_modules:
        for name, obj in inspect.getmembers(m):
            if inspect.isclass(obj) and \
                    issubclass(obj, operators.Operator) and \
                    hasattr(obj, "operator_name"):
                installed_ops[obj.operator_name] = obj
    print "found ops:", ', '.join(installed_ops.iterkeys())

def get_operator(name, args):
    """Look up an operator by name.  If given args, try to parse them
    using whatever initializer lists are available.

    :raises: ParseException if it can't match the operator
    """
    groups = filter(lambda x: type(x) == type('') and x[0] == '$', args)
    args = filter(lambda x: type(x) != type('') or x[0] != '$', args)

    if not name in installed_ops:
        raise qg.QueryException("No such operator: " + name)
    if len(args) == 0:
        # if the op doesn't take any args, just return the bare operator
        return installed_ops[name]
    else:
        for proto in installed_ops[name].operator_constructors:
            if len(proto) != len(args): continue
            try:
                alist = map(lambda (fn, a): fn(a), zip(proto, args))
            except ValueError:
                continue
            return lambda inputs: installed_ops[name](inputs, *alist)
        raise qg.QueryException("No valid constructor for operator %s: %s" % 
                                (name, str(args)))

def make_applicator(ops, group=None):
    class _TmpOp(operators.CompositionOperator):
        oplist = ops

    def build_result((d, s)):
        obj = dict(s)
        d[:,0] = np.int_(d[:, 0])
        d[:,0] *= 1000
        obj['Readings'] = d.tolist()
        return util.build_recursive(obj, suppress=[])

    def apply_op(data):
        opmeta = data[0][1]
        opmeta = map(lambda x: dict(util.buildkv('', x)), opmeta)
        if not len(opmeta):
            return []

        # build the operator
        if group and len(group):
            op = operators.GroupByTagOperator(opmeta, _TmpOp, group[0])
        else:
            op = _TmpOp(opmeta)

        # insert the data in the right index for the operator (it
        # could come back in any order)
        opdata = [operators.null] * len(data[1][1])
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
    
discover()
