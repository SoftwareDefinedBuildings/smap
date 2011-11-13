Tutorial
========

In this tutorial you will learn how to:

* Create a simple sMAP source from an existing driver
* Write a sMAP driver
* Manage the destination of data using the :py:class:`smap.reporting.Reporting` module

Your First sMAP Source
----------------------
.. py:currentmodule:: smap.driver

A common use case is to use an existing sMAP driver to publish data
from a sensor or actuator.  A list of available sMAP drivers is not
yet available, but you can look at the modules available in
``python/smap/drivers``.  In order to start a sMAP source using an
existing driver, you first create a configuration file and then use
the sMAP runtime to start the daemon.

One driver which is distributed with the distribution is the
California ISO price driver.  This driver scrapes price data from the
the ISO's web site, and republishes it as a sMAP feed.  Drivers are
implemented by python classes, so the most important thing to know is
the full name of the driver in question; this one is called
:py:class:`smap.drivers.caiso_price.CaIsoPrice`.

Once you know the name of the driver, you need to create a
configuration file which tells the sMAP runtime about the source you
want to create.  An example which uses this driver is::

 [/]
 uuid = fc778450-b191-11e0-bb60-0026bb56ec92
 Metadata/SourceName = CA ISO price feed
 
 [/OAKLAND]
 type = smap.drivers.caiso_price.CaIsoPrice
 Location = OAKLAND_1_N001

We've mapped in the driver under the ``/OAKLAND`` resource; all feeds
provided by this driver will be underneath that resource.  The
Location parameter is passed to the driver, and tells it what ISO
"node" to scrape.  We'll get to what ``uuid`` and
``Metadata/SourceName`` do later on.

Once you have this config file (available in
``python/conf/caiso_price.ini``), you can run the source by typing in
the ``python`` directory::

 $ twistd -n smap conf/caiso.ini 
 2011-07-19 14:20:59-0700 [-] Log opened.
 2011-07-19 14:21:00-0700 [-] twisted.web.server.Site starting on 8080
 2011-07-19 14:21:00-0700 [-] Starting factory <twisted.web.server.Site instance at 0x901498c>
 2011-07-19 14:21:00-0700 [-] get_readings DAM

And that's it!  You're running.  To consume your source, try::

 $ jprint http://localhost:8080/data/+

``jprint`` is a convienient tool which will pretty-print your json and
should be in your path, but you can also use `curl <http://curl.haxx.se/>`_.

Adding Metadata
---------------

It's often useful to tag your streams with additional information
about them -- sampling rate, what kind of instrument you're using, and
so on.  To do this, you can include metadata in each section of your
config file.  In the example above, the ``Metadata/SourceName`` line
is an example of this.  This tag should always be set to a
human-readable name which your smap source may be referred to by.

Metadata is added by "tagging" your streams.  To make this easy,
metadata applies to all timeseries originating below the place it is
added to.  Above, the ``Metadata/SourceName`` tag applies to all
streams located below "/"; therefore, all streams created by the
CaIsoPrice driver, in this case.

The tagging namespace is slightly structured to enable the use of some
shared tags; there are three "subspaces" which you may use:

===================== =========================
Subspace              Contents
===================== =========================
Metadata/Location/*   Information relating to the location of the data
Metadata/Instrument/* Information about the instrument which created the data
Metadata/Extra/*      Arbitrary extra information
===================== =========================

The Location and Instrument subspaces have a pre-defined set of keys
which you should use to structure your tags; see :ref:`metadata-tags`.

Writing Drivers
---------------

A common design pattern is to implement a "driver" for a type of
instrument, and then copy that driver to represent multiple
instruments of the same class.  For instance, you would write
one driver for the Dent electric meter, and then connect that driver
to new Dent meters which are mapped into the sMAP hierarchy.

To support this important case, we have provided the
:py:mod:`smap.driver` module.  Writing a driver is not really any
harder than not writing a driver, so we strongly encourage you to
use this framework.
    
Conceptually, a "driver" is a place in the resource hierarchy
under which all the resources are added and implemented
programmatically.  To be a driver, you need to implement two
methods; the :py:class:`smap.driver.BaseDriver` class is one
example::
    
  class BaseDriver(driver.SmapDriver):
      def setup(self, opts):
          self.add_timeseries('/sensor0', 'V')
          self.set_metadata('/sensor0', { 
              'Instrument/ModelName' : 'ExampleInstrument'
              })
          self.counter = int(opts.get('StartVal', 0))

      def start(self):
          util.periodicSequentialCall(self.read).start(1)

      def read(self):
          self.add('/sensor0', self.counter)
          self.counter += 1

To start a sMAP instance which exposes only this driver, you can use
the ``smap-run-driver`` tool; this example is available as
:py:class:`smap.driver.BaseDriver`::

 $ smap-run-driver smap.driver.BaseDriver

We can also have this all done from a config file.  Typically, you
would debug your driver first inside of ``smap-run-driver`` before
inflicting it on the wider world.  Let's modify the old config
snippet from before::

  [/]
  uuid = 75503ac2-abf0-11e0-b7d6-0026bb56ec92
  Metadata/SourceName = Base Example Driver

  [/instrument0]
  type = smap.driver.BaseDriver
  Metadata/Instrument/Manufacturer = sMAP Implementer Forum
  StartVal = 10

We can now run this just as easily as before either using ``twistd``.

When writing a driver, paths should be relative to a root path ("/")
and not include any other path components; the full path is created by
combining the attachment point from the config file (``/instrument0``)
with the paths supplied in the driver (``/sensor0``), so the full path
of this sensor is ``/instrument0/sensor0``.  Paths used to create
timeseries and collections inside of a driver only need to be unique
within that driver, not the whole sMAP source because the keys are
combined with the driver's UUID to generate their full identifier.

When created from a config file, the second parameter to setup is a
dict whose keys are keys from the appropriate section of the
configuration file, and the corresponding values.  You can use this
mechanism to pass arguments to your drivers; in this example we can
tell the driver to start counting at 10 rather than 0 (the default).


Recitative: Threads and Events
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Twisted is an event system -- everything runs in a single main loop,
and nothing can block.  You're welcome to use all of the twisted
library when implementing your sMAP source; just make sure nothing
blocks.  The typical way to interface with twisted is by registering
callbacks to run in the main loop, using either 
:py:meth:`twisted.internet.reactor.runFromThread`, which
schedules a callback to be run in the main thread, or the
:py:class:`twisted.internet.task.LoopingTask` class which sets up a
callback to be called repeatedly.

Since a common idiom in sMAP sources is to periodically poll an
external device using a blocking API, we have provided the
:py:func:`smap.util.periodicSequentialCall` function to periodically
call a callback from a separate thread from the main event loop.  It
also guarantees that there will only be one copy of your updater
running at a given time.  This means you may not use any
non-thread-safe :py:mod:`twisted` methods; however you may use normal
blocking APIs::

  import util
  def readValue(val):
      print "Reading value:", val
  util.periodicSequentialCall(readValue, 1).start(1)

Adding Data
~~~~~~~~~~~

Now that we've discussed some of the perils and pitfalls of the
:py:mod:`twisted` concurrency model, we're ready to generate some
data!  Let's assume that we've set up our instance like above, but
haven't yet started running the server::

  counter = 1
  def read():
     global counter
     inst.add('/sensor0', counter)
     counter += 1
  util.periodicSequentialCall(read).start(1)

This example will add sequential values to our sensor, at a rate of
once per second (that's set by the argument to start).  In this
example, we used the version of :py:meth:`SmapInstance.add` which
automatically timestamps your reading with the current system time.
``read()`` will be called in a separate thread once a second, which
means it's okay to use blocking io in the body.  You would typically
poll your device, interpret the response, and update a number of sMAP
points in such a body.


Data Destination: Where does the Data go?
-----------------------------------------

sMAP sends out its data via HTTP POST requests to data sinks who are
interested in the data.  These consumers can get configured in one of
two ways: the first is via the sMAP-specified mechanism, a POST
request to the ``/reports`` resource on a sMAP server.  The reports can
also be configured via a config file section.

An example configuration file snippet::

  [report 0]
  ReportDeliveryLocation = http://new.openbms.org/backend/add/MYAPIKEY

Any section starting with the string "report" is treated as a
reporting instance.  ``ReportDeliveryLocation`` specifies
the URI data will be posted to.

Buffering
~~~~~~~~~

sMAP implementers are often interested in having their data reliably
reach their consumers regardless of network failure or downtime on the
consumer side.  Therefore, the sMAP library contains a per-consumer
buffer which tracks data which has been generated by the source but
not yet delivered.  By default, the :py:mod:`reporting` module will
store up to 10000 values per stream in a circular buffer.  This data
is written back to disk, so that it can be delivered even if the sMAP
server crashes or is restarted.  Data is only removed from the buffer
once the library receives a HTTP ``200 OK``, ``201 CREATED``, or ``204
NO CONTENT`` responses from the destination server.

