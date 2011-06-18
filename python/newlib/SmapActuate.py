
import time
import urlparse

class SmapActuator:
    """Base class for actuators, which deals with HTTP.
    """
    def __init__(self, lock=None, unit=None, pushfn=None):
        self.lock = lock
        self.unit = unit
        self.pushfn = pushfn

    def _call_locked(self, fn):
        """Call a function.  If this actuator was created with a lock, we'll
call the function holding that lock.  Otherwise, we'll make a call
that could be concurrent if multiple threads hold references to this
object"""
        if self.lock != None:
            with self.lock:
                return fn()
        else:
            return fn()

    def valid_state(self, state):
        return False

    def change(self, request, new_state):
        if self.valid_state(new_state):
            self._call_locked(lambda: self.set_state(request, new_state))
            if self.pushfn != None:
                self.pushfn()

    def http_get(self, request, resource, query=None):
        if len(resource) == 0:
            query = urlparse.parse_qs(query)
            if len(query.get('state', [])) == 1:
                self.change(request, query['state'][0])
                
            rv = {
                'Version' : 1,
                'ControlerType' : self.control_type,
                'CurrentState' : self._call_locked(lambda: self.get_state(request))
                }
            if self.unit:
                rv['UnitofMeasure'] = self.unit

            rv.update(self.control_description)
            return rv
        elif resource[0] == 'reading':
            return {
                'Version' : 1,
                'Reading' : self._call_locked(lambda: self.get_state(request)),
                'ReadingTime' : time.time()
                }
        else:
            return None


class BinaryActuator(SmapActuator):
    """A BinaryActuator is a controller which has only two states,
generally "on" and "off".  It is essentially a simplified version of
an NStateActuator.

State here are static and can't be configured.
    """
    def valid_state(self, state):
        return reduce(lambda x,y: x or state in y, 
                      self.control_description['States'], 
                      False)

    def __init__(self, **kwargs):
        self.control_type = 'binary'
        self.control_description = {
            'States' : [['0', 'off'], ['1', 'on']]
            }
        SmapActuator.__init__(self, **kwargs)


class NStateActuator(SmapActuator):
    """NStateActuators have a discrete number of states which they can be
in.  Although there may be restrictions on which state transisitions
are possible, this profile does not express any of them.
    """
    def __init__(self, n_states, **kwargs):
        self.control_type = 'nstate'
        SmapActuator.__init__(self, **kwargs)


class ContinuousActuator(SmapActuator):
    """A ContinuousActuator allows a set point to be adjusted within a
continuous interval.  Minimum and maximum values in the range must be
specified.
    """
    def valid_state(self, state):
        return float(state) >= self.control_description['States'][0] and \
            float(state) <= self.control_description['States'][1]

    def __init__(self, range=None, **kwargs):
        self.control_type = 'continuous'
        self.control_description = {
            'States' : range,
            }
        SmapActuator.__init__(self, **kwargs)


class GuardBandActuator(SmapActuator):
    """A GuardBandActuator actually consists of two points -- "high" and
"low", which are adjusted in parallel.
    """
    def __init__(self, **kwargs):
        self.control_type = 'guardband'
        SmapActuator.__init__(self, **kwargs)


if __name__ == '__main__':
    import threading
    import SmapHttp
    from SmapAuthorization import authenticated

    class MyActuator(BinaryActuator):
        def __init__(self):
            BinaryActuator.__init__(self, lock=threading.Lock())
            self.state = 0

        def get_state(self, request):
            return self.state

        @authenticated(["CAP_SECURE"])
        def set_state(self, request, state):
            print "Setting state to", state
            self.state = state

    class MyOtherActuator(ContinuousActuator):
        def get_state(self, request):
            return self.state
        def set_state(self, request, state):
            print "Setting state to", state
            self.state = state
    
    a = MyActuator()
    b = MyOtherActuator(range=[0, 5])
    SmapHttp.start_server({'a': a, 'b': b}, port=8000, handler=SmapHttp.SslSmapHandler)
