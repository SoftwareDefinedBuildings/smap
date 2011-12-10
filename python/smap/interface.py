
from zope.interface import Interface, implements

class ITimeseries(Interface):
    """Represent a single time series -- one stream of scalars
    """
    def add(self, *args):
        """Add a new reading to this timeseries.
        
        This version is thread-safe -- can be called from any thread.
        """

    def _add(self, *args):
        """Add a new reading to this timeseries.

        This version should only be called from the twisted main loop.
        """

    def render(self):
        pass

class ITimeseriesFactory(Interface):
    def __call__(unit, 
                 data_type="integer", 
                 timezone="America/Los_Angeles",
                 key=None,
                 new_uuid=None, 
                 buffersz=1):
        """Create a Timeseries

        We set the default data type to Integer and timezone to the
        West Coast, so the only *required* information is the unit of
        measure for this stream.

        If both key and uuid are None, there is an exception because
        one of these is needed to assign the timeseries a UUID.
        Otherwise, "uuid" is used first, followed by a uuid generated
        algorithm 5 based on key + smap.root_uuid.

        @buffersz how many readings are stored in the Reading resource
        (for GET requests, reporting is handled separately).
        """
        print "__CALL__"

class ICollection(Interface):
    """Represent a collection of resources, with attached metadata
    """
    def add_child(self, child):
        """Add a child to the collection"""

    def render(self):
        pass

class IActuator(Interface):
    def setup(self, opts):
        """Set up an actuator"""

    def parse_state(self, state):
        """Parse a state from a string into a state representation"""

    def set_state(self, state):
        """Set the state of the actuator.  The value passed in as the
        new state will be the result of calling parse_state"""

    def get_state(self, state):
        """Read the current state of the actuator.  This should query
        the device for the state, rather than using a cached value."""

class ISmapInstance(Interface):
    """Represents a sMAP instance -- a whole tree of Collections and Timeseries.
    """
    
    def lookup(self, id, pred=None):
        """Look up a sMAP point relative by path or uuid.

        Thread-safe version
        """
    def get_timeseries(self, id):
        """Get a timeseries by identifier"""
    def get_collection(self, id):
        """Get a collection by identifier"""

    def add_timeseries(self, path, *args, **kwargs):
        pass
    def add_collection(self, path, collection):
        pass

class IReporting(Interface):
    """Represents a reporting object, which is responsible for sending
    data to interested consumers.
    """

    def add_report(self, rpt):
        pass
    def get_report(self, rpt):
        pass
    def update_report(self, rpt):
        pass

    def update_subscriptions(self):
        pass

    def publish(self):
        pass


    def _flush(self, force=False):
        """Try to send out all data which is able to be sent currently

        @force ignore MinPeriod and MaxPeriod requests in the reporting instance
        @return a deferred which will fire when all the data has
             delivered.  Any errors in delivery will cause the errBack
             to fire instead.
        """

    def flush(self):
        pass

class ISmapDriver(Interface):
    """Represent a sMAP driver -- something which attaches itself at
    some point in the tree and then may produce readings
    """
    def setup(self, instance, opts={}):
        """The driver should register its points with the relative
        sMAP instance in this call.

        @instance an object implementing ISmapInstanve
        @opts dict of other options to be passed to the driver, ie from a config file
        """

    def start(self):
        """Called when the instance should start producing readings.        
        """
