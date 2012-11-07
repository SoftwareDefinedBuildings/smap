Writing Scraping Drivers
========================

A common pattern for driver writing is to periodically fetch data from
a source, parse it, and add it to the sMAP server.  To make this this
easy to implement, we provide a driver template which can take care of
the mechanics of periodically fetching data called
:py:class:`smap.driver.FetchDriver`.

Simple HTTP example
-------------------

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
attempts to load data from the specified uri every rate seconds.

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
----------------------------

If what you have is an XML document, you might want to use XSLT to
pull out the readings.  :py:class:`smap.drivers.xml.XMLDriver`
provides the ability to do this.  As an example, consider the data
produced by an Obvius Aquisuite device; see an example 
`data file <obvius-data.xml>`_.  You can transform this file into sMAP-XML using a
simple XSLT transform and generate a driver using this config file::

 [/]
 uuid = 6fa21782-27b2-11e2-9a49-370ecdac5e02

 [/obvius]
 type = smap.drivers.xml.XMLDriver
 Uri = http://un:pw@aquisuite.example.com/setup/devicexml.cgi?ADDRESS=24&TYPE=DATA
 Xslt = xslt/obvius.xsl
 Timeformat = %Y-%m-%d %H:%M:%S

This driver periodically loads the obvius document over http, converts
it using the XSLT stylesheet, and then adds the data.  Timeformat is a
python `strptime` time string used to parse the timestamps found in
the transformed xml.