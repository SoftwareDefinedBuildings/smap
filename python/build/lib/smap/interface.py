
from zope.interface import Interface, implements

class ITimeseries(Interface):
    def add(self, time, value, seqno=None):
        """Add a new reading to this timeseries."""

    def get_uuid(self):
        """Return the UUID of this timeseries (as a uuid object)."""

    def get_metadata(self):
        """Return the collection's Metadata."""

    def set_metadata(self, meta):
        """Set a new metadata object.  Will throw a SmapSchemaException if it
        was an invalid object."""

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

    def add_child(self, child):
        """Add a child to the collection"""
    def get_metadata(self):
        """Return the collection's Metadata"""

    def get_elementmap(self):
        """Return the mapping from string name to UUID"""

