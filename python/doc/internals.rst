Additional topics
=================

sMAP source conf file syntax
----------------------------

The sMAP library lets you easily set up a source using a configuration
file.  This way, you can easily set up a source for your site, with
all the setup in one place.  sMAP uses the :py:mod:`configobj`
module to parse the config file, so you can use its syntax.

To set up a source, you define the resource hierarchy the sMAP source
presents.  Each path that the source exports is either a Collection, a
Timeseries, or a driver.  By putting them in a config file, you can
add tags to any resource; tags in the config file will override tags
added by the driver.

Root Section
~~~~~~~~~~~~

Each configuration file must have one section named ``[/]``, the root
section.  This must contain at least a ``uuid`` directive::

 [/]
 uuid = 62cc6ed0-ed30-11e0-b74a-f3caa83aee0f

This uuid is used in order to control uuid assignment for many other
parts of the sMAP source.  For instance, if you don't provide a uuid
in other sections, the sMAP driver will generate one for you by
combining this uuid with those sections' pathnames.

Other Sections
~~~~~~~~~~~~~~

All other sections of the resource tree are defined in sections
starting with a ``/``.  For instance, you can use the test driver
which comes distributed with sMAP::

 [/test]
 type = smap.driver.BaseDriver

The meaning of this section is to create a driver implemented by the
:py:class:`smap.driver.BaseDriver` class, and place it into the tree
at ``/test``.  Since we did not provided either a ``uuid`` key or a
``key`` directive, the id for this driver will be generate by
combining the string ``/test`` with the root uuid as the namespace.

All sections having to do with the resource tree may also be tagged
with metadata using keys described in :ref:`metadata-tags`.

Server Section
~~~~~~~~~~~~~~

A section called ``[server]`` controls options to be used by the sMAP
server.  There are several option::

 [server]
 Port = 8070
 DataDir = /var/run/smap

The ``Port`` option controls which port sMAP's HTTP server runs on;
the default is port 8080.  The ``DataDir`` option controls where the
on-disk log of data which has been added but not delivered is stored.
The default is the current directory; it should be set to a writable
directory.

sMAP Direct
~~~~~~~~~~~

The sMAP daemon will serve static files from a directory on disk; you
can use this to build custom browser-based UI's for your sMAP source.
By default, the sources run "sMAP Direct" -- a simple browser
interface to your data and controls.  The ``docroot`` parameter
controls where this directory it is::

 [server]
 Port = 8070
 docroot = /var/www/smap

If you don't wish to use this feature, simply set it to the empty
string (``docroot = ``).

SSL Support
~~~~~~~~~~~

You can configure the sMAP server to run over SSL if you'd like to
secure actuation.  To do this, you'll have to supply a server
certificate and private key; if you wish to verify client
certificates, you'll also need a trust root (a certificate authority).
You can include these options in the ``[server]`` block::

 [server]
 sslport = 8000
 cert = server1.crt
 key = server1.pem
 ca = root.crt
 # verify = true

If you set ``verify = true``, the server will reject clients whos
certificate is not signed (directly or indirectly) by the certificate
authority; the ``ca`` option is required to use this.

Reports Section
~~~~~~~~~~~~~~~

You can also configure destinations for data in sections named
``[report(.*)]``; the section names should start with ``report`` and
can be followed by any string.

Each report section must contain at least a
``ReportDelieveryLocation`` key, whose value is a URL.  sMAP will send
data to that URL in the body of an HTTP POST::

 [report 0]
 ReportDeliveryLocation = http://jackalope.cs.berkeley.edu/~sdawson/receive.php

If you want to add redundant destinations, you can add them using the
``ReportDeliveryLocation[0-9]`` keys::

 [report 0]
 ReportDeliveryLocation = http://jackalope.cs.berkeley.edu/~sdawson/receive.php
 ReportDeliveryLocation0 = http://backup.cs.berkeley.edu/~sdawson/receive.php

If the primary server isn't accepting data, sMAP will try to deliver
data to the backup locations in a round-robin fashion; so long as the
current server is working it will continue to use it so this really
creates a "pool" of destinations which may be used.  sMAP will
continue to store outgoing data on disk and attempt to deliver it
until it receives an HTTP success code (200, 201, or 204) from one of
the destinations in the pool.

Programatically creating sMAP sources
-------------------------------------

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
stream.  If you don't include this argument, the path will be used.
Finally, 'V' is the units of the stream: volts.

``my_timeseries`` holds the newly created :py:class:`Timeseries` object.
You can also get that back by looking it up by path in the instance::

  inst.get_timeseries('/sensor0')

Finally, to start a web server serving this instance, we just need to
set up a server and start the ``twisted`` event loop.  The
:py:mod:`smap.server` module has a wrapper to do this for us::

  server.run(inst, port=8080)

You're now running a sMAP server on HTTP port 8080!  Cool, right?  One
problem: how to actually generate some data?


Loading sources from config files
---------------------------------

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

