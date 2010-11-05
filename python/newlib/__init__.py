"""newlib sMAP library

The newlib library contains a reference implementation of the sMAP
application protocol for exposing physical data over the HTTP.

All sMAP sources available in this distribution are implemented using
this library; the simplest one is devices.test.TestSmap.

To build a new sMAP source, first create one or more new SmapInstances
-- instructions for doing so are in that module's pydoc.  Then, start
the sMAP server using the SmapHttp.start_server utility function.
Finally, implement an updater to add new records to the sMAP feed.
You may find the util.RateTimer class useful for implementing a
periodic update.
"""

__all__ = ['SmapPoint', 'SmapHttp', 'SmapInstance', 'smaplog', 
           'series', 'util']
