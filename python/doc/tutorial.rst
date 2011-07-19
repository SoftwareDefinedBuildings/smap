Tutorial
========

In this tutorial you will learn how to:

* Programatically create a simple sMAP source
* Load an equivalent simple sMAP source from a configuration file
* Write a sMAP driver
* Manage the destination of data using the :py:class:`smap.reporting.Reporting` module
* Write a sMAP importer

Your First sMAP Source
----------------------

.. py:currentmodule:: smap.core

The core of any sMAP source is the :py:class:`~smap.core.SmapInstance`
class.  Even if you're not running a web server, you'll need to create
a :py:class:`SmapInstance` to represent the hierarchy and structure of
the sMAP source you are working with.

To create a new :py:class:`SmapInstance`, all you need is a UUID.
This UUID is very important, because it will become the identifier for
the root of your source, and will be the name by which other people
can refer to you (even if you change other fields).  You should use
the same UUID each time you create the same sMAP source, so that ids
do not change with each execution.

The library comes with a tool called ``uuid`` which you can used to
generate a new, unique UUID; you can also get one using the
:py:mod:`uuid` module.  Once you have one of these, we can instantiate
our first sMAP instance::

  from smap import core, server, util
  inst = core.SmapInstance('75503ac2-abf0-11e0-b7d6-0026bb56ec92')

When you create an instance, by default it has one collection: the
root collection (``/``).  Typically you will want to add other
collections and timeseries to this collection.  You may also want to
add metadata to allow the consumers to tell what they are looking at.
The :py:class:`SmapInstance` class has utility methods
:py:meth:`~SmapInstance.add_collection` and
:py:meth:`~SmapInstance.add_timeseries` to help you do this.

Let's add a single timeseries to our sMAP source::

  my_timeseries = inst.add_timeseries('/sensor0', 'sensor0', 'V')

In this example, we just added a single timeseries which will be
located at ``/data/sensor0``.  The second argument, 'sensor0', is a
key which durably names this timeseries.  This way, you can change the
path but consumers will still be able to tell that it's the same
stream.  Finally, 'V' is the units of the stream: volts.

``my_timeseries`` holds the newly created :py:class:`Timeseries` object.
You can also get that back by looking it up by path in the instance::

  inst.get_timeseries('/sensor0')

Finally, to start a web server serving this instance, we just need to
set up a server and start the ``twisted`` event loop.  The
:py:mod:`smap.server` module has a wrapper to do this for us::

  server.run(inst, port=8080)

You're now running a sMAP server on HTTP port 8080!  Cool, right?  One
problem: how to actually generate some data?

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
:py:func:`smap.util.periodicCallInThread` function to
periodically call a callback from a separate thread from the main event
loop.  This means you may not use any non-thread-safe :py:mod:`twisted`
methods; however you may use normal blocking APIs::

  import util
  def readValue(val):
      print "Reading value:", val
  util.periodicCallInThread(readValue, 1).start(1)

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
  util.periodicCallInThread(read).start(1)

This example will add sequential values to our sensor, at a rate of
once per second (that's set by the argument to start).  In this
example, we used the version of :py:meth:`SmapInstance.add` which
automatically timestamps your reading with the current system time.
``read()`` will be called in a separate thread once a second, which
means it's okay to use blocking io in the body.  You would typically
poll your device, interpret the response, and update a number of sMAP
points in such a body.

sMAP Sources From Config Files
------------------------------

Creating a sMAP source programmatically is nice, but sometimes you
just want more out of life.  To get you there, we've helpfully
provided the :py:mod:`smap.loader` module.  A loader can create a
sMAP source from a configuration file, or dump an existing sMAP source
to a config file.  Typically, you'll create part of a sMAP source in a
driver (the next section!) and then generate an instance using a config file.

Let's see what happens if we dump the sMAP source from the previous
section to a config file using :py:func:`~smap.loader.dump`::

   from smap import loader
   loader.dump(inst, 'conf.ini')

We end up with a configuration file ``conf.ini`` in the directory
where we ran that command::

    [/]
    type = Collection
    uuid = 75503ac2-abf0-11e0-b7d6-0026bb56ec92

    [/sensor0]
    type = Timeseries
    key = sensor0
    Properties/UnitofMeasure = V
    
As you can see, the UUID we entered for the root has been saved,
as well as parameters for the timeseries which is placed at
``/sensor0``.  Let's modify the hierarchy by creating a new
collection which contains ``sensor0``, and also add some metadata
which applies to the collection::
    
    [/]
    type = Collection
    uuid = 75503ac2-abf0-11e0-b7d6-0026bb56ec92

    [/instrument0]
    type = Collection
    Metadata/Instrument/Manufacturer = sMAP Implementer Forum
    
    [/instrument0/sensor0]
    type = Timeseries
    key = sensor0
    Properties/UnitofMeasure = V

We've added a new key, ``Metadata/Instrument/Manufacturer``.  Since
this path refers to part of sMAP's metadata specification, this will
store that metadata with that collection.

Now, let's instantiate and serve a sMAP server using this conf, this
time using :py:func:`~smap.loader.load` to generate the instance from
the config file::

  from smap import core, util, loader, server
  inst = loader.load('conf.ini')
  server.run(inst, port=8080)

Check it out with ``$ curl localhost:8080/data/instrument0/sensor0 | jprint``::

  {
    "Properties": {
      "ReadingType": "long", 
      "Timezone": "America/Los_Angeles", 
      "UnitofMeasure": "V"
    }, 
    "Readings": [], 
    "uuid": "c2f2cb69-25cc-544c-87cc-3b807c58f63a"
  }

sMAP Drivers
------------

.. py:currentmodule:: smap.driver

So far, you've seen how to create an instance and add data to it
in a thread.  However, a common design pattern is to implement a
"driver" for a type of instrument, and then copy that driver to
represent multiple instruments of the same class.  For instance,
you would want to write one driver for the Dent electric meter,
and then connect that driver to new Dent meters which are mapped
into the sMAP hierarchy.

To support this important case, we have provided the
:py:mod:`smap.driver` module.  Writing a driver is not really any
harder than not writing a driver, so we strongly encourage you to
use this framework.  
    
Conceptually, a "driver" is a place in the resource hierarchy
under which all the resources are added and implemented
programmatically.  To be a driver, you need to implement two
methods; the :py:class:`smap.driver.BaseDriver` class is one
example::
    
  class BaseDriver:
      def setup(self, inst, opts):
          selt.ts = inst.add_timeseries('/sensor0', 'mysensor', 'V')

      def start(self):
          self.counter = 0
          util.periodicCallInThread(self.read).start(1)

      def read(self):
          self.t.add(self.counter)
          self.counter += 1

It implements the same functionality as our previous two examples,
except now we can replicate this instrument as may times as we wish.
To start a sMAP instance which exposes only this driver, we need just
a little bit of glue; here's the whole example::

  from smap import driver, server, core
  inst = core.SmapInstance('75503ac2-abf0-11e0-b7d6-0026bb56ec92')
  drv = driver.BaseDriver()
  drv.setup(inst, {})
  drv.start()
  server.run(inst)

We can also have this all done from a config file; let's modify the
old config snip[pet from before::

  [/]
  type = Collection
  uuid = 75503ac2-abf0-11e0-b7d6-0026bb56ec92

  [/instrument0]
  type = smap.driver.BaseDriver
  Metadata/Instrument/Manufacturer = sMAP Implementer Forum

We can now run this just as easily as before::

  inst = loader.load('conf.ini')
  server.run(inst)

The keys or paths which are used to create timeseries and collections
inside of a driver only need to be unique within that driver, not the
whole sMAP source because the keys are combined with the driver's UUID
to generate their full identifier.

When created from a config file, the second parameter to setup is a
dict whose keys are keys from the appropriate section of the
configuration file, and the corresponding values.  You can use this
mechanism to pass arguments to your drivers; for instance, tell it how
to connect to the instrument being proxied.

Running into Production
~~~~~~~~~~~~~~~~~~~~~~~

As you start to write a lot of sMAP sources, you'll want to be able to
test your code and then move it into production.  Usually, you'll
first want to test out your driver; the sMAP distribution provides two
tools for doing this.

The first, ``run-driver`` will start up a sMAP instance and try to
load a driver classname passed in on the command line, and map that
driver in as the resource root.  For instance::

 $ bin/run-driver smap.drivers.caiso.CaIsoDriver

Runs the smap driver for the California ISO.

Data Destination: Where does the Data go?
-----------------------------------------

sMAP sends out its data via HTTP POST requests to data sinks who are
interested in the data.  These consumers can get configured in one of
two ways: the first is via the sMAP-specified mechanism, a POST
request to the ``/reports`` resource on a sMAP server.  The reports can
also be configured via a config file section, in case the data is
merely being loaded and there's no need for a server.

An example configuration file snippet::

  [report 0]
  ReportDeliveryLocation = http://jackalope.cs.berkeley.edu/~sdawson/receive.php
  ReportResource = /+

Any section starting with the string "report" is treated as a
reporting instance, and both of these options are required.  The
first, ``ReportDeliveryLocation`` specifies the URI data will be
posted to.  


The second, ``ReportResource`` tells the library what local resource
to package up to send out.  It is interpreted relative to the root
``/data`` resource -- those are the only things you can subscribe to.
Any valid resource under ``/data`` can be subscribed to.  Each
collection additionally contains a special resource,
``+``. This can be used to
to *all* timeseries subordinate to the given resource.

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
