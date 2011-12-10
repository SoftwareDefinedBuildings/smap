"""Classes for supporting performing actuation with sMAP.

sMAP services with actuation components should place actuators at the
leaves of their resource tree, replacing SmapPoint instances.
Generally, the steps necessary to provide actuation is simply to
subclass the appropriate actuator class (Binary, NState, or
Continuous), and then implement the get_state and set_state methods.

Services wishing to use access control should additionally use SSL for
authentication, and annotate their get and set methods with the
appropriate capabilities necessary to access those resources.
"""
import time
import urlparse
import core
import util
import traceback

from twisted.internet import defer
from zope.interface import implements
from interface import *

class RateLimiter:
    """Class for rate-limiting function call

    @ratelimit minimum time between method calls.  If None,
      method_if_allowed will never be called.  If callable, will allow
      the call if it returns True.
    @method_if_allowed method to be called if allowed by the rate limit
    @method_if_disallowed 
    @return (boolean, result) the boolean indicates if the call was
      allowed by the rate limit, and the result is the result of calling
      the appropriate method

    Since this class overwrites __call__, you can get the result of
    calling the appropriate method just by "calling" this class.it 
    """
    def __init__(self, ratelimit, method_if_allowed=None, method_if_disallowed=None):
        self.ratelimit = ratelimit
        self.method_if_allowed = method_if_allowed
        self.method_if_disallowed = method_if_disallowed
        self.last_value = None
        self.last_call = 0

    def __call__(self, *args, **kwargs):
        allowed = False
        rv = None
        now = time.time()
        print now, self.last_call
        if (callable(self.ratelimit) and self.ratelimit()) or \
                (util.is_integer(self.ratelimit) and \
                     now - self.last_call > self.ratelimit):
            allowed = True
            if self.method_if_allowed:
                rv = self.method_if_allowed(*args, **kwargs)
            self.last_call = now
        elif self.method_if_disallowed:
            rv = self.method_if_disallowed(*args, **kwargs)

        return allowed, rv

class SmapActuator(core.Timeseries):
    """Base class for actuators, which deals with HTTP and timing
    requirements.  You must implement three functions for each
    actuator: parse_state, get_state, and set_state.  For common
    actuator classes, parse_state is already done.

    get_state and set_state should be stub functions which talk
    directly to the device; if you wish to use cached value to limit
    the device request rate, you should set read_limit appropriately.

    @unit the value for the UnitofMeasure sMAP field
    @read_limit a value, in seconds, of how often get_state may be
       called.  if not None, the class will call get_state at most once per
       given interval, and otherwise return the last read value that was 
       recorded by calling add().  if None, get_state will never be called and 
       will always return the state recored by calling add().
    @write_limit the same as read_limit, but for set_state.  If
       set_state is called more frequently than this limit, the server
       will return an HTTP error code.
    """
    implements(IActuator)

    def __init__(self, new_uuid, unit, read_limit=0, write_limit=0, autoadd=True, **tsargs):
        core.Timeseries.__init__(self, new_uuid, unit, **tsargs)
        self.FIELDS.append("Actuate")
        self.reader = RateLimiter(read_limit, 
                                  lambda req: util.syncMaybeDeferred(self.get_state, req), 
                                  lambda req: core.Timeseries.render(self, req))
        self.writer = RateLimiter(write_limit, 
                                  lambda req, state: util.syncMaybeDeferred(self.set_state, req, state))
        self.autoadd = autoadd
        self.__setitem__('Actuate', {
                'Model' : self.ACTUATE_MODEL
                })

    def valid_state(self, state):
        """Determine if a given state is valid for a particular actuator.

        The state will be the result of calling parse_state.
        @prototype
        """
        return False

    def parse_state(self, state):
        """Parse a string representation of a state
        @prototype
        """
        return state

    def render(self, request):
        if request.method == 'GET':
            return self.render_read(request)
        elif request.method == 'PUT':
            return self.render_write(request)

    def render_write(self, request):
        """Render a request to change the state"""
        if 'state' in request.args and len(request.args['state']) > 0:
            new_state = self.parse_state(request.args['state'][0])
            if not self.valid_state(new_state):
                raise core.SmapException("Invalid state: " + str(new_state), 400)

            allowed, d = self.writer(request, new_state)
            if allowed:
                d.addCallback(lambda x: self._accept_result_render(request, x))
                return d
            else:
                raise core.SmapException("Cannot actuate now due to rate limit", 503)

    def render_read(self, request):
        """Render the read

        The rate limiter will make sure that we don't overload the
        device; it will used the Timeseries cached value if we've
        called it too much.
        """
        allowed, rv = self.reader(request)
        if allowed:
            rv.addCallback(lambda x: self._accept_result_render(request, x))
        return rv

    def _accept_result_render(self, request, state):
        # now start a render of the underlying TS object
        d = defer.maybeDeferred(core.Timeseries.render, self, request)
        d.addCallback(lambda x: self._finish_render(state, x))
        return d

    def _finish_render(self, state, tsrender):
        # finish by adding the current state as the reading
        now = util.now()

        if self.autoadd:
            self.add(now, state)

        tsrender = dict(tsrender)
        tsrender['Readings'] = [(util.now() * 1000, state)]
        return tsrender


class BinaryActuator(SmapActuator):
    """A BinaryActuator is a controller which has only two states,
generally "on" and "off".  It is essentially a simplified version of
an NStateActuator.

State here are static and can't be configured.
    """
    ACTUATE_MODEL = 'binary'

    def valid_state(self, state):
        return state == 0 or state == 1

    def parse_state(self, state):
        for s in self.control_description['States']:
            if state.strip().lower() in s:
                return int(s[0])
        return None

    def setup(self, opts):
        self.control_type = 'binary'
        self.control_description = {
            'States' : [['0', 'off'], ['1', 'on']]
            }


class NStateActuator(SmapActuator):
    """NStateActuators have a discrete number of states which they can be
in.  Although there may be restrictions on which state transisitions
are possible, this profile does not express any of them.
    """
    ACTUATE_MODEL = 'discrete'
    def valid_state(self, state):
        return int(state) in self.control_description['States']
    
    def __init__(self, states, *args, **kwargs):
        self.control_type = 'nstate'
        self.control_description = {
            'States' : states,
            }
        SmapActuator.__init__(self, **kwargs)


class ContinuousActuator(SmapActuator):
    """A ContinuousActuator allows a set point to be adjusted within a
continuous interval.  Minimum and maximum values in the range must be
specified.
    """
    ACTUATE_MODEL = 'continuous'
    def valid_state(self, state):
        return state >= self.control_description['States'][0] and \
            state <= self.control_description['States'][1]

    def parse_state(self, state):
        return float(state)

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
    import uuid
    import server
    import json
    import sys
    from twisted.python import log
    from authentication import authenticated
    log.startLogging(sys.stdout)
    inst = core.SmapInstance('f80d0504-f2c6-11e0-80e6-ebc97648cfa4')


    class MyActuator(BinaryActuator):
        def setup(self, opts):
            self.state = 0
            BinaryActuator.setup(self, opts)

        def get_state(self, request):
            print request
            print "getting"
            self.add(self.state)
            return self.state
        
        @authenticated(["__has_ssl__"])
        def set_state(self, request, state):
            print "Setting state to", request,state
            self.state = state
            return self.state

#     class MyOtherActuator(ContinuousActuator):
#         def get_state(self, request):
#             return self.state
#         def set_state(self, request, state):
#             print "Setting state to", state
#             self.state = state
    act = MyActuator(inst.uuid('/a1'), 'UoM')
    import actuate

    inst.add_timeseries('/a1', act)
    inst.add_timeseries('/t1', 'V')
    rl = RateLimiter(10)
    
    a2 = inst.add_actuator('/a2', 'UoM', MyActuator, 
                           read_limit=10,
                           write_limit=10,
                           setup={})
    server.run(inst, port=8080)
#     a = MyActuator()
#     b = MyOtherActuator(range=[0, 5])
#     SmapHttp.start_server({'a': a, 'b': b}, port=8000, handler=SmapHttp.SslSmapHandler)
