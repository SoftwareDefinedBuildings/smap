sMAP Internals
==============

the Instance
------------

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
