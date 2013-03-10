
Patterns for driver writing
===========================

There are many patterns for driver-writing, organized around how the
underlying instrumentation is accessed.  sMAP provides special support
for some types of sources.

.. _periodic-scraping:

Periodic scraping
-----------------

A common pattern for driver writing is to periodically fetch data from
a source, parse it, and add it to the sMAP server.  To make this this
easy to implement, we provide a driver template which can take care of
the mechanics of periodically fetching data called
:py:class:`smap.driver.FetchDriver`.

Simple HTTP example
~~~~~~~~~~~~~~~~~~~

You can use this driver as the parent class of a more specialized
driver; for instance one which extracts fields from a CSV file.  As an
example, suppose we have a source which periodically publishes a file
to a web server with a single temperature in it::

 $ curl http://example.com/data.txt
 10.46

To expose this as a sMAP source, we could write the following simple driver::

 from smap.driver import FetchDriver

 class SimpleDriver(FetchDriver):
     def setup(self, opts):
         FetchDriver.setup(self, opts)
         self.add_timeseries('/data', 'C')

     def process(self, data):
         self.add('/data', float(data))

By implementing the ``process`` method, we put our source-specific
processing logic in one place; however, the actually logic for
downloading the page is elsewhere.

Configuring your driver
~~~~~~~~~~~~~~~~~~~~~~~

In addition to whatever configuration options your driver may take,
``FetchDriver`` takes two options: ``Uri`` and ``Rate``.  The driver
attempts to load data from the specified URI every rate seconds.

The driver currently understands three URI schemes:

============ =============================================== ===========================
Scheme       Format                                          Description
============ =============================================== ===========================
http, https  http://[username:password]@netloc/path;p?q#f    Data from HTTP; username and password are optional
file         file://<absolute path>                          Data from a file
python       python://module.name.load_function              Data loaded by calling a python module
============ =============================================== ===========================

Running the example
~~~~~~~~~~~~~~~~~~~

In this case, we want to use HTTP without a username or password, so
we can just create a simple configuration file::

 [/]
 uuid = 6fa21782-27b2-11e2-9a49-370ecdac5e02

 [/example]
 type = example.SimpleDriver
 Uri = http://example.com/data.txt
 Rate = 30

More Complicated XML Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If what you have is an XML document, you might want to use XSLT to
pull out the readings.  :py:class:`smap.drivers.xslt.XMLDriver`
provides the ability to do this.  As an example, consider the data
produced by an Obvius Aquisuite device; see an example 
`data file <obvius-data.xml>`_.  You can transform this file into sMAP-XML using a
simple XSLT transform and generate a driver using this config file::

 [/]
 uuid = 6fa21782-27b2-11e2-9a49-370ecdac5e02

 [/obvius]
 type = smap.drivers.xslt.XMLDriver
 Uri = http://un:pw@aquisuite.example.com/setup/devicexml.cgi?ADDRESS=24&TYPE=DATA
 Xslt = xslt/obvius.xsl
 Timeformat = %Y-%m-%d %H:%M:%S

This driver periodically loads the obvius document over http, converts
it using the XSLT stylesheet, and then adds the data.  Timeformat is a
python `strptime` time string used to parse the timestamps found in
the transformed xml.

.. _actuation:

Actuation
---------

A key part of sMAP is supporting the actuation of points.  Actuation
presents additional concerns beyond simple data collection, for a few
reasons:

* Often, sMAP must access underlying devices in response to a request,
  rather than asynchronously as part of a polling loop
* Authentication and authorization are most likely required

:py:class:`smap.actuate` contains base classes needed for actuation.
They provide the ability to create a sMAP point which maps to an
underlying actuator.  

Simple Example Actuator
~~~~~~~~~~~~~~~~~~~~~~~

Implementing an actuator is slightly more involved than a simple
timeseries.  The first step is to implement a class which provides the
actual communication with the underlying device.  The class of the
actuator determines what kind of inputs can be made -- is it a switch,
with only two states? or perhaps it allows any floating-point value
within a range as in a setpoint control.

This is a simple actuator from :py:class:`smap.drivers.file` which
allows you to "actuate" using an underlying file on the filesystem::

  class FileActuator(actuate.BinaryActuator):
      """Example Binary Acutator which implements actuation by writing
      to a file
      """

      def setup(self, opts):
          actuate.BinaryActuator.setup(self, opts)
          self.file = os.path.expanduser(opts['filename'])

      def get_state(self, request):
          with open(self.file, 'r') as fp:
              return int(fp.read())

      def set_state(self, request, state):
          with open(self.file, 'w') as fp:
              fp.write(str(state))
          return state

A few key points to notice:

1. The actuator inherits from a
   :py:class:`~smap.actuate.BinaryActuator`.  This means it can be in
   only one of two positions (on/off, 1/0).
2. We implemented two methods -- ``get_state`` and ``set_state`` to
   actually perform the actuation.  These will be called from an HTTP
   request handler so there are some concerns about them.
    
Implementing get_state and set_state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
These functions implement the actual logic for talking to your device.
Since we're using twisted, you should not block inside of these
methods (I cheated a little bit by reading a file in the example).
You may, however, return a
:py:class:`~twisted.internet.defer.Deferred` which will fire with the
result; however, since any HTTP requests will wait until you produce a
value you should make sure to either produce a result or an error
within a reasonable amount of time.

The value (or result of the deferred) for both methods should be a
valid value for the actuator type in question.  Every actuator class
has a ``valid_state(state)`` method which returns True if the state
variable contains a valid value; for instance; the
:py:class:`smap.actuate.BinaryActuator` class allows only 0 or 1 as
valid states.

Building a Driver with Actuators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you've built your actuator, you'll want to include it in a
driver.  This is also relatively simple::

  class FileDriver(driver.SmapDriver):
      """Driver which creates a single point backed by a file.  You
      could use this, for instance, to expose flags in /proc"""
      def setup(self, opts):
          filename = opts.pop('Filename', '~/FileActuatorFile')
          self.add_actuator('/point0', 'Switch Position',
                            FileActuator, setup={'filename': filename})

Just like when adding a :py:class:`~smap.core.Timeseries` to a sMAP
server, we add an actuator with a path (``/point0``) and unit
(``Switch Position``).  Because this is an actuator, we also specify the
classname of the actuation class with the logic we want to expose.  As
you can see, the ``setup`` dict will be passed to the setup method of
the actuator; in this case we use it to choose what file the actuator
is controlling.

Rate Limiting
~~~~~~~~~~~~~

Frequently, you'll want to rate-limit how often the underlying
actuator is accessed.  You can control this when adding the actuator
using the ``read_limit`` and ``write_limit`` keyword args. Take, for
instance::

  self.add_actuator('/point0', 'Switch Position',
                    FileActuator, setup={'filename': filename},
                    read_limit=1, write_limit=1)

Now, we'll return an ``HTTP 503 Service Unavailable`` if we access
the actuator more than once per second.

Actuator Classes
~~~~~~~~~~~~~~~~

We have defined several different actuator classes that cover common
types of actuation as part of 

================================= ====================== ===========================
Actuator class                    Description            Valid states
================================= ====================== ===========================
``BinaryActuator()``              Two-state actuator     0/1 or on/off
``NStateActuator(statelist)``     Discrete actuator      Any value in ``statelist``
``IntegerActuator()``                                    Any integer
``ContinuousActuator((lo, hi))``  Values inside a range  ``value >= lo and value <= hi``
================================= ====================== ===========================

Full Example
~~~~~~~~~~~~

The conf file in ``python/conf/example.ini`` includes a file actuation
driver for demonstration purposes::

  [/actuator0]
  type = smap.drivers.file.FileDriver
  Filename = ~/smap-actuator.txt

This creates a file actuator backed by the file
``~/smap-actuator.txt``.  The sMAP server will return errors until
that file is created; however, you can change the state of that file
using HTTP requests, once that driver is running::

  # create the file
  echo 1 > ~/smap-actuator.txt

  # get the current value
  curl http://localhost:8080/data/actuator0/point0
  {"Properties": {"Timezone": "America/Los_Angeles", "UnitofMeasure": "Switch Position", "ReadingType": "long"}, "Actuate": {"Model": "binary"}, "uuid": "7afaa0a6-7719-5c1b-ae38-0f03b6d35256", "Readings": [[1354064481000, 0]]}

  # change the state
  curl  -XPUT localhost:8080/data/actuator0/point0?state=1
  {"Properties": {"Timezone": "America/Los_Angeles", "UnitofMeasure": "Switch Position", "ReadingType": "long"}, "Actuate": {"Model": "binary"}, "uuid": "7afaa0a6-7719-5c1b-ae38-0f03b6d35256", "Readings": [[1354064507000, 1]]} 