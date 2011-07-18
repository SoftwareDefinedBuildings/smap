Introduction to sMAP
====================

Welcome! sMAP, or the Simple Measurement and Actuation Profile is a
specification for a protocol designed to allow users to expose and
publish data from a wide variety of sensors simply and flexibly.

The documentation on this web page refers exclusively to the version
of the specification as of version 1.1.

sMAP Basics
-----------

At its core, sMAP provides a facility for publishing *collections* and
*time series*. A time series is a single stream of scalar-valued
readings which have some logical association with each other -- they
are typically produced by an instrument channel.  A collection is an
unordered set of these timeseries.  sMAP allows collections to nest,
so the contents of collections is either other collections, or time
series.

sMAP specifies schemas for both collections and time series.  It
additionally specifies how these abstract objects can be exposed over
HTTP, and provides a method for callbacks to provide notifications of
new data or events.  Each of these objects are globally identified by
Universal Unique Identifiers (UUID's), which are 128-bit names
generated to be unique with high probability.  Although each resource
or object in a sMAP server is distinguished by one of these
identifiers, the standard library tries (as much as possible) to
prevent users from needing to generate or manage these keys; typically
it is only necessary to specify a single UUID for a sMAP instance, and
all others will be deterministically generated from that id.

Library Functionality
---------------------

For a full specification of the sMAP protocol, we refer the reader to
other documentation.  The purpose of this library is to implement sMAP
in such a way as to make it extremely easy to write new sMAP sources.

The sMAP library is implemented using :py:mod:`twisted`, an
asynchronous event system for python.  It takes care of serving up
sMAP resources over HTTP and managing data being sent to various
subscribers.  It supports both programmatic creation of sMAP server,
creating a server from a configuration file, or a combination.

Installation
------------

Dependencies
~~~~~~~~~~~~

* `python 2.6, 2.7 <http://www.python.org>`_
* `twisted 11 <http://www.twistedmatrix.com>`_
