
import inspect
import numpy as np

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
        raise qg.ParseException("No valid constructor for operator %s: %s" % (name, str(args)))

def make_applicator(ops, (extractor, sql)):
    class _TmpOp(operators.CompositionOperator):
        oplist = ops

    def apply_op(data):
        opmeta = [{'uuid': x['uuid'],
                   'Properties/UnitofMeasure': ''} for x in data]
        opdata = [np.array(x['Readings']) if len(x['Readings']) else operators.nulla
                  for x in data]
        op = _TmpOp(opmeta)
        return op.process(opdata)

    def applicator(*args):
        d = extractor(*args)
        d.addCallback(apply_op)
        return d

    return applicator, sql
    
discover()
