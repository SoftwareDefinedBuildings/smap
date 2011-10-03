The sMAP Configuration File
===========================

The sMAP library lets you easily set up a source using a configuration
file.  This way, you can easily set up a source for your site, with
all the setup in one place.  sMAP uses the :py:mod:`configparser`
module to parse the config file, so you can use its syntax.

To set up a source, you define the resource hierarchy the sMAP source
presents.  Each path that the source exports is either a Collection, a
Timeseries, or a driver.  By putting them in a config file, you can
add tags to any resource; tags in the config file will override tags
added by the driver.

Root Section
------------

Each configuration file must have one section named ``[/]``, the root
section.  This must contain at least a ``uuid`` directive::

 [/]
 uuid = 62cc6ed0-ed30-11e0-b74a-f3caa83aee0f

This uuid is used in order to control uuid assignment for many other
parts of the sMAP source.  For instance, if you don't provide a uuid
in other sections, the sMAP driver will generate one for you by
combining this uuid with those sections' pathnames.

Other Sections
--------------

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
--------------

A section called ``[server]`` controls options to be used by the sMAP
server.  There are two options::

 [server]
 Port = 8070
 DataDir = /var/run/smap

The ``Port`` option controls which port sMAP's HTTP server runs on;
the default is port 8080.  The ``DataDir`` option controls where the
on-disk log of data which has been added but not delivered is stored.
The default is the current directory; it should be set to a writable
directory.

Reports Section
---------------

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