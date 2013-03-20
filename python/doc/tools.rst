sMAP toolbox
============

smap-query
----------

.. _smap-monitize:

smap-monitize
-------------

smap-load
---------

description
++++++++++

The ``smap-load`` command line tool is used to load historical data through a driver
into an archive and can be used with drivers that have a ``load`` method. The ``load``
method takes start- and end-datetime arguments that define the range of data to be 
loaded into the archive, as well as a boolean keyword argument for a cache option.
An example signature of a ``load`` method is::

  load(start_time, end_time, cache=None)

where ``start_time`` and ``end_time`` are Python ``datetime`` objects that will be
passed by ``smap-load``. In the body of the ``load`` method, return a ``deferred``
object with the appropriate callbacks. Here is a simple example of a load method
from the ``example`` driver::  

    def load(self, st, et, cache=None):
        d = threads.deferToThread(self.load_data, st, et)
        return d
    def load_data(self, st, et):
        st_utc = dtutil.dt2ts(st)
        et_utc = dtutil.dt2ts(et)
        ts = st_utc
        while ts <= et_utc:
            self._add('/sensor0', ts, self.counter)
            self.counter += 1
            ts += 120 # 2-min increments

The following options are available:

  ``-h``, ``--help``
        Show the help message.
  ``-t TIMEFMT``, ``--timefmt=TIMEFMT``
        Time format of the ``START_TIME`` and ``END_TIME`` arguments, specified
        with Python datetime directives found at 
        http://docs.python.org/2/library/time.html#time.strptime. *Default: "%m-%d-%Y"*
  ``-s START_TIME``, ``--start-time=START_TIME``
        Start time of the import (format set by ``--timefmt``). *Default: 1 hour ago*
  ``-e END_TIME``, ``--end-time=END_TIME``
        End time of the import (format set by ``--timefmt``). *Default: now*
  ``-z TIMEZONE``, ``--timezone=TIMEZONE``
        Time zone for conversion. *Default: Local timezone*
  ``-r``, ``--reset``
        Reset drivers before running.
  ``-n``, ``--no-cache``
        Don't cache downloaded data. This will set the ``cache`` option to ``False``.

examples
++++++++

A common use-case of smap-load is to archive aggregated data from an operator expression.
This might include resampling data, summing streams, or performing other arithemtic
operations on streams. Here we will demonstrate use of ``smap-load`` in two steps. First
we will consider the ``example.py`` driver and corresponding ``example.ini`` configuration
file, and archive data over the course of a day. Next we will use the expression driver 
to create a stream of 15-minute averages of the data we archived in step one.

In the first step, we will archive one day's worth of data running the ``example.ini``
configuration file. This will simply archive data from a counter that is incremented by
one every two minutes. Suppose the time range is from 3/15/2013 - 3/16/2013::

    smap-load -s "3-15-2013" -e "3-16-2013" example.ini

Suppose instead that we want to load data in the range 3/17/2013 5:00PM - 3/18/2013 5:00PM.
This results in a more complicated date format that we'll set with ``--timefmt``::

    smap-load -s "3-11-2013 17:00" -e "3-12-2013 17:00" -t "%m-%d-%Y %H:%M" example.ini

Next, we'll construct a configuration file that will drive windowing operation::

    [server]
    Port = 8082
    
    [report 0]
    ReportDeliveryLocation = http://new.openbms.org/backend/add/pRUT0SLcupKVhpazofV97vpcSsyvtPIDmVNY
    ReportResource = /+
    
    [/]
    uuid = 19f32dab-90ef-11e2-a482-e4ce8f4229ee
    
    [/sensor0-15min]
    type = smap.drivers.expr.ExprDriver
    Expression 15min = "window(mean, field='minute', width=15)"
    Group = uuid
    ChunkSize = 48
    Restrict = Path='/instrument0/sensor0'

Suppose this file is named example_window.ini We can now use this to create 15-minute 
averages of the data from step one::

    smap-load -s "3-15-2013" -e "3-16-2013" example_window.ini

smap-load-csv
-------------

description
+++++++++++

The ``smap-load-csv`` command line tool can be used to insert existing data in csv 
format as sMAP streams into an archive. 

The following options are available:

  ``-h``, ``--help`` 
        Show the help message.
  ``-u UUID``, ``--uuid=UUID`` 
        The channels of the csv file will be imported as a collection. This option 
        will set the UUID of the collection which is the root or parent of all the 
        channels in the csv file. *default: uuid will be generated*
  ``-i IGNORE``, ``--ignore-channels=IGNORE`` 
        Ignore specific channels during the import. ``IGNORE`` takes the form of a comma
        separated list of channel names (as defined in the channel headers in the csv
        file) or channel numbers (enumerated starting with 0). The channels not contained
        in this list will be archived. *default: none*
   ``-c TAKES``, ``--take-channels=TAKES``
        Choose specific channels to be archived from the csv file. ``TAKES`` is in the
        form of a comma separated list of channel names (as defined in the channel
        headers in the csv file) or channel numbers (enumerated starting with 0).
        The channels not contained in this list will be ignored. *default: all*
  ``-t TIME``, ``--time-channel=TIME``
        The channel number or name of the channel containing date and time data. The
        channel numbers are enumerated starting with 0. *default: 0*
  ``-f TIME_FORMAT``, ``--time-format=TIME_FORMAT``
        The format of the data contained in channel specified with ``--time-channel``.
        This is specified using the python date/time format directives, which can be
        found at http://docs.python.org/2/library/time.html#time.strptime. *default: 
        "%s" (Seconds since UNIX epoch)*
  ``-z TIME_ZONE``, ``--time-zone=TIME_ZONE``
        The name of the time zone. *default: "America/Los_Angeles"*
  ``-d REPORT_DEST``, ``--report-dest=REPORT_DEST``
        The url of the archiver in which to insert the data collected from the csv file.
        This should point to the ``add`` resource of the archiver followed by the API
        key if applicable. *default: none **this option is required***
  ``-v``, ``--verbose``
        Verbose console output for debugging or monitoring the import.
  ``-k SKIP_LINES``, ``--skip-lines=SKIP_LINES``
        The number of lines to skip in the target csv file. This allows the user to easily
        discard superfluous header data. *default: 0*
  ``-l LIMIT``, ``--limit-lines=LIMIT``
        The maximum number of lines to process from the target csv file. *default: none*
  ``-s SOURCE_NAME``, ``--source-name=SOURCE_NAME``
        The value of the Metadata/SourceName tag. *default: "CSV Input"*

example
+++++++

To explain the use of the smap-load-csv 
command line tool, we will refer to the following example csv file that 
uses several options as ``ex.csv``. This file contains time series 
data describing an air terminal unit spanning one hour::

  Dev 1076,,,,,
  Some,,,,,
  Headers,,,,,
  Time,Space Temperature,Cooling Setpoint,Heating Setpoint,Supply Air Temperature,CFM
  5/2/2011 9:05,74,74,68,69,896
  5/2/2011 9:15,74.5,74,68,68.8,888
  5/2/2011 9:25,74.5,74,68,68.1,919
  5/2/2011 9:35,74.5,74,68,67.7,1000
  5/2/2011 9:45,74.5,74,68,67.3,1050
  5/2/2011 9:55,74.5,74,68,67,1139
  5/2/2011 10:05,74.5,74,68,66.2,1208

Specify where you want to send the data contained in the csv file with the
``--report-dest`` option. This shoud be set to be the location of the add resource 
in the sMAP archiver. For this example we will set 
``--report-dest=http://localhost:8079/add/<key>``.

One of the channels must contain time data. The format and channel number are 
specified in the command with ``--time-format`` and ``--time-channel``. Set the 
``--time-channel`` option to the channel number of the time data (note that 
channel numbers are enumerated starting with 0). Our time data is located in the 
first column, so ``--time-channel`` is the default of 0. Provide the time format 
with the ``--time-format`` option by using python's strptime date directives 
(http://docs.python.org/2/library/time.html#time.strptime). The time format in 
ex.csv is ``%d/%m/%Y %H:%M`` corresponding to a timestamp like ``5/2/2011 09:05``. 

In order to specify which channels or columns to read and send to the archiver, 
use the command-line option ``--ignore-channels`` or ``--take-channels``. If the
``--ignore-channels`` option is used, all channels not ignored will be read and 
archived. If the ``--take-channels`` option is used, only those channels will be 
archived. Supposing we want to ignore the ``Cooling Setpoint`` and ``Heating 
Setpoint`` columns, we may set ``--ignore-channels=2,3``. Equivalently, we could
take the other columns by setting ``--take-channels=1,4,5``. The names of columns 
can be used instead of channel numbers.

If the csv file being processed has lines of text that precede the channel headers
and should be skipped, the ``--skip-lines option`` can be used. ``ex.csv`` contains 
a few lines of headers that we'd like to skip, so we set ``--skip-lines=3``.

Finally, the source name is set with ``--source-name``. In our example we will set 
``--source-name=Example``

Putting it all together, we arrive at the following command::

  smap-load-csv --source-name=Example --skip-lines=3 --ignore-channels=2,3 --time-format="%d/%m/%Y %H:%M" --report-dest=http://localhost:8079/add/<key> ex.csv

smap-tool
---------
