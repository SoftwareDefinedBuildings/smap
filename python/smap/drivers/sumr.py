
import uuid
import numpy as np
from scipy.stats import nanmean

from smap.core import SmapException
from smap.archiver.client import SmapClient
from smap.operators import *
from smap import util
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

def joinedsub(inputs):
    assert len(inputs) == 2
    vals = np.subtract(*map(lambda x: x[:,1], inputs))
    return [np.dstack((inputs[0][:,0], vals))[0]]
    
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

class _SubtractOperator(Operator):
    name = 'subtract'
    process = staticmethod(joinedsub)

class OrderOperator(Operator):
    def __init__(self, inputs, order_tag):
        self.name = 'order-by-%s' % order_tag
        Operator.__init__(self, inputs, OP_N_TO_N)
        self.reorder = map(operator.itemgetter(0),
            sorted(enumerate(inputs), key=lambda x: x[1][order_tag]))

    def process(self, inputs):
        # apply the operator to the reordered inputs
        return map(lambda x: inputs[x], self.reorder)

class BucketOperator(GroupbyTimeOperator):
    name = 'bucketed mean operator'
    operator_name = 'bucket'
    operator_constructors = [(),
                             (int,),
                             (int, float)]
    def __init__(self, inputs, chunk_length=10, chunk_delay=1):
        GroupbyTimeOperator.__init__(self, inputs,
                                     _MeanVectorOperator, 
                                     chunk_length, chunk_delay)


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
                             (int,),
                             (int, float, float)]

    def __init__(self, inputs, windowsz=300, delay=1.0, data_fraction=0.9):
        self.name = 'sum-%i' % windowsz
        self.oplist = [  
            StandardizeUnitsOperator,

            lambda inputs: GroupbyTimeOperator(inputs,
                                               _MeanVectorOperator,
                                               chunk_length=windowsz,
                                               chunk_delay=delay),

            lambda inputs: o._MissingDataOperator(inputs, data_fraction),

            # gotta fix them units before we add
            StandardizeUnitsOperator,

            # then take the mean across all feeds
            _SumOperator,

            # snap times to window starts
            lambda inputs: SnapTimes(inputs, windowsz),
            # PrintOperator,
            ]
        CompositionOperator.__init__(self, inputs)
        

class SubtractOperator(CompositionOperator):
    """Compute the mean of differences of streams
    """
    name = "subtract"
    operator_name = 'subtract'
    operator_constructors = [(str,),
                             (str, int)]

    def __init__(self, inputs, inner_order=None, windowsz=300):
        self.oplist = [
            lambda inputs: GroupbyTimeOperator(inputs, 
                                               _MeanVectorOperator,
                                               chunk_length=windowsz),
            lambda inputs: OrderOperator(inputs, inner_order),
            _SubtractOperator,
            lambda inputs: SnapTimes(inputs, windowsz),
            # PrintOperator,
            ]
        CompositionOperator.__init__(self, inputs)

class WindowedDriver(GroupedOperatorDriver):
    INIT_ARGS = (
        ('Window', 'windowsz', 300, int, True),
        ('Delay', 'delay', None, float, False),
        ('DataFraction', 'data_fraction', None, float, False),
        ('OrderKey', 'inner_order', None, str, False),
        )

    def setup(self, opts):
        kwargs = {}
        for arg in self.INIT_ARGS:
            name, argname, default, cvtr, mandatory = arg
            if mandatory or name in opts:
                val = opts.get(name, default)
                kwargs[argname] = cvtr(val)

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

class SubtractDriver(WindowedDriver):
    inner_operator = SubtractOperator

if __name__ == '__main__':
    ip = [{
            'uuid' : '7ebdde28-44a9-11e1-8968-00508dca5a06',
            'tag' : 'foo',
            },
          {
            'uuid' : '7f2fef2c-44a9-11e1-afa5-00508dca5a06',
            'tag' : 'boo',
            }]
    
    # o = OrderedArithmeticOperator(ip, 'tag')
    o = SubtractOperator(ip, 'tag')
    print o([np.array([[0, 1], [600, 2]]), 
             np.array([[0, 2], [600, 3]])])
