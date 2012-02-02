
import uuid
import numpy as np
from scipy.stats import nanmean

from smap.core import SmapException
from smap.archiver.client import SmapClient
from smap.operators import *
import smap.operators as o

def _mean(vec):
    """Take the mean of both the timestamps and the values"""
    if len(vec) == 0:
        return null, {}
    else:
        return np.array([np.mean(vec, axis=0)]), {}

def joinedop(op, inputs):
    vals = op(map(lambda x: x[:,1], inputs), axis=0)
    return [np.dstack((inputs[0][:,0], vals))[0]]

joinedsum = lambda input: joinedop(np.nansum, input)
joinedmean = lambda input: joinedop(nanmean, input)
joinedmedian = lambda input: joinedop(np.median, input)

##
## Buffering operators. BufferedJoinOperator and LatestOperator are
## often placed at the head of the processing chain, so later
## operators can operate on windows of data.
##
##
## Mean operators with different semantics
##
class _MeanOperator(Operator):
    """Mean operator which requires all data to be present and
    timestamps to be aligned"""
    name = 'mean'
    process = staticmethod(joinedmean)

class _MeanVectorOperator(ParallelSimpleOperator):
    """Take the mean of all data presented from N feeds"""
    name = 'mean vector'
    base_operator = staticmethod(_mean)

class _SumOperator(Operator):
    name = 'sum'
    process = staticmethod(joinedsum)

class OrderedOperator(Operator):
    def __init__(self, inputs, order_tag, op="np.subtract"):
        self.name = 'order-by-%s' % order_tag
        Operator.__init__(self, inputs, OP_N_TO_1)
        self.reorder = map(operator.itemgetter(0),
            sorted(enumerate(inputs), key=lambda x: x[1][order_tag]))
        self.op = eval(op)

    def process(self, inputs):
        # apply the operator to the reordered inputs
        v = self.op(*map(lambda x: inputs[x][:, 1], self.reorder))
        return [np.dstack((inputs[0][:,0], v))[0]]

##
## Subsampling operators
##
##
## Useful operators made up of streams of other operators
##
class SubsampledSumOperator(CompositionOperator):
    """Add up N streams by first bucketing and then buffering data
    until data from all streams are present.
    """
    name = 'subsampled sum'
    def __init__(self, inputs, windowsz):
        self.windowsz = windowsz
        self.oplist = [
            StandardizeUnitsOperator,
##            PrintOperator,
            lambda inputs: SubsampleOperator(inputs, self.windowsz),
            BufferedJoinOperator,
            _SumOperator]
        CompositionOperator.__init__(self, inputs)

class MissingSumOperator(CompositionOperator):
    name = "sum with missing data"
    def __init__(self, inputs, windowsz, missingthresh=0.6):
        self.oplist = [
            StandardizeUnitsOperator,
            lambda inputs: GroupbyTimeOperator(inputs, 
                                               lambda x: SubsampleOperator(x, windowsz),
                                               chunk_length=windowsz),
            lambda inputs: o._MissingDataOperator(inputs, missingthresh),
            # PrintOperator,
            _SumOperator,
            ]
        CompositionOperator.__init__(self, inputs)


class SubsampleMeanOperator(CompositionOperator):
    name = 'subsample-mean'
    operator_name = 'subsample'
    operator_constructors = [(int,)]

    def __init__(self, inputs, windowsz=300000):
        self.oplist = [
            # take the mean of each bucket
            lambda inputs: GroupbyTimeOperator(inputs,
                                               _MeanVectorOperator,
                                               chunk_length=windowsz),
            # but snap the timestamps to the beginning of the window
            lambda inputs: SnapTimes(inputs, windowsz),
            ]
        CompositionOperator.__init__(self, inputs)


class MeanOperator(CompositionOperator):
    """Maintain a mean of N streams 
    """
    name = 'Mean'
    operator_name = 'mean'
    operator_constructors = [(int, )]
    def __init__(self, inputs, windowsz=300):
        self.oplist = [
            lambda inputs: GroupbyTimeOperator(inputs,
                                               _MeanVectorOperator,
                                               chunk_length=windowsz),
            
            # then take the mean across all feeds
            _MeanOperator,

            # snap times to window starts
            lambda inputs: SnapTimes(inputs, windowsz),
            ]
        CompositionOperator.__init__(self, inputs)

class SumOperator(CompositionOperator):
    operator_name = 'sum'
    operator_constructors = [(),
                             (int,)]

    def __init__(self, inputs, windowsz=300, delay=1.0, data_fraction=0.9):
        self.name = 'sum-%i' % windowsz
        self.oplist = [
            StandardizeUnitsOperator,

            lambda inputs: GroupbyTimeOperator(inputs,
                                               _MeanVectorOperator,
                                               chunk_length=windowsz,
                                               chunk_delay=delay),

            lambda inputs: o._MissingDataOperator(inputs, data_fraction),

            # then take the mean across all feeds
            _SumOperator,

            # snap times to window starts
            lambda inputs: SnapTimes(inputs, windowsz),
            # PrintOperator,
            ]
        CompositionOperator.__init__(self, inputs)
        

class DifferenceMeanOperator(CompositionOperator):
    """Compute the mean of differences of streams
    """
    name = "difference-mean"
    def __init__(self, inputs, inner_order, windowsz=300):
        self.oplist = [
            lambda inputs: GroupbyTimeOperator(inputs, 
                                               _MeanVectorOperator,
                                               chunk_length=windowsz),
            lambda inputs: OrderedOperator(inputs, inner_order),
            _MeanOperator,
            lambda inputs: SnapTimes(self, inputs)
            ]
        CompositionOperator.__init__(self, inputs)

class WindowedDriver(GroupedOperatorDriver):
    def setup(self, opts):
        windowsz = int(opts.get("Window", 300))
        delay = opts.get("Delay", None)
        datafrac = opts.get("DataFraction", None)
        kwargs = {'windowsz': windowsz}
        if delay: kwargs['delay'] = float(delay)
        if datafrac: kwargs['data_fraction'] = float(datafrac)

        self.operator_class = (lambda x: self.inner_operator(x, **kwargs))
        GroupedOperatorDriver.setup(self, opts)


class DefaultSummationDriver(WindowedDriver):
    inner_operator = SubsampledSumOperator

class MissingSummationDriver(WindowedDriver):
    inner_operator = MissingSumOperator

class SubsampleMeanDriver(WindowedDriver):
    inner_operator = SubsampleMeanOperator
        
class MeanDriver(WindowedDriver):
    inner_operator = MeanOperator

class SumDriver(WindowedDriver):
    inner_operator = SumOperator

if __name__ == '__main__':
    ip = [{
            'uuid' : '7ebdde28-44a9-11e1-8968-00508dca5a06',
            'tag' : 'foo',
            },
          {
            'uuid' : '7f2fef2c-44a9-11e1-afa5-00508dca5a06',
            'tag' : 'goo',
            }]
    
    o = OrderedArithmeticOperator(ip, 'tag')
    o([np.array([[0, 1], [1, 2]]), np.array([[0, 2], [1, 3]])])
