
.. _driver-index:

Driver Index
============

Part of the goal of sMAP is to foster a community support open data
aquisition of many different devices.  This page has a partial list of
drivers distributed with sMAP as part of the :py:mod:`smap.drivers` package.

Unless otherwise specified, arguments without a default value are required.

Generic Drivers
---------------

XML
~~~

**Module**: ``smap.drivers.xml.XMLDriver``

**Communications**: XML over file, http, or python loader

**Data**: whatever is exposed through the XSLT transform

+------------+---------------------------------------------------------------------------------------------------+---------------+
| Parameter  | Description                                                                                       | Default Value |
+============+===================================================================================================+===============+
| Uri        | URI to load: supported schemes are http, https, file, and python                                  |               |
+------------+---------------------------------------------------------------------------------------------------+---------------+
| Rate       | Polling frequency (seconds)                                                                       | 30            |
+------------+---------------------------------------------------------------------------------------------------+---------------+
| Xslt       | XSLT transformation to apply to document to convert it to sMAP-XML                                |               |
+------------+---------------------------------------------------------------------------------------------------+---------------+
| Timeformat | python strptime string used to parse the time in the document.                                    | %s            |
+------------+---------------------------------------------------------------------------------------------------+---------------+
| Timezone   | zone code for the data; the timeformat will be parsed as if it is a local timestamp in this zone. | UTC           |
+------------+---------------------------------------------------------------------------------------------------+---------------+

XSLT is a way of applying a declarative transformation to XML documents.  Sometimes you can use that to very easily convert existing XML data into sMAP feeds.  There are a few sample XSLT transformation available in trunk/xslt:


+-------------------+-------------------------------------------------------------------------------------+
| Stylesheet        | Description                                                                         |
+===================+=====================================================================================+
| `greenbutton.xsl` | Transformation for US GreenButton data packed inside of Atom(http://naesb.org/espi) |
+-------------------+-------------------------------------------------------------------------------------+
| `obvius.xsl`      | Generic transformation for Obvius Aquisuite XML data                                |
+-------------------+-------------------------------------------------------------------------------------+
| `ted5000.xsl`     | Transform for the Ted 5000 which exports all channels                               |
+-------------------+-------------------------------------------------------------------------------------+

Expression Driver
~~~~~~~~~~~~~~~~~

**Module**: ``smap.drivers.expr.ExprDriver``


+------------+------------------------------------------------------------------------+---------------+
| Parameter  | Description                                                            | Default Value |
+============+========================================================================+===============+
| Expression | An operator expression to compute                                      |               |
+------------+------------------------------------------------------------------------+---------------+
| Restrict   | An ArdQuery where-clause restricting the set of input streams          |               |
+------------+------------------------------------------------------------------------+---------------+
| Group      | A tagname specifying how streams are groups when passed into operators |               |
+------------+------------------------------------------------------------------------+---------------+

The expression driver is a way to compute ArdQuery operator expressions over new data.  This gives you a way to create new "virtual" sMAP streams based on other data.  The driver will create streams corresponding to the output of the query

.. code-block:: python

  apply _Expression_ to data before now where _Restrict_ group by _Group_

As new data arrives, it will be pushed through the expression and published as a new sMAP feed.  To avoid circularity, it's a good idea to make _Restrict_ include at least ``has Path and not has Metadata/Extra/Operator``.

Electric Meters
---------------


Dent PowerScout 18
~~~~~~~~~~~~~~~~~~

**Module**: ``smap.drivers.dent.Dent18``

**Communications**: Modbus over TCP

**Data**: 6 three-phase electric meters

+------------+-------------------------------------------+---------------+
| Parameter  | Description                               | Default Value |
+============+===========================================+===============+
| Address    | Hostname of device (or Modbus/IP gateway) |               |
+------------+-------------------------------------------+---------------+
| Port       | Port                                      | 4660          |
+------------+-------------------------------------------+---------------+
| ModbusBase | Device modbus address                     | 1             |
+------------+-------------------------------------------+---------------+
| Rate       | Polling frequency (seconds)               | 20            |
+------------+-------------------------------------------+---------------+

Veris E30 Panel Meter
~~~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.veris.VerisDriver``

**Communications**: Modbus over TCP

**Data**: 42 single-phase power and energy measurements

+-----------+-------------------------------------------+---------------+
| Parameter | Description                               | Default Value |
+===========+===========================================+===============+
| Address   | Hostname of device (or Modbus/IP gateway) |               |
+-----------+-------------------------------------------+---------------+
| Port      | Port                                      |               |
+-----------+-------------------------------------------+---------------+
| BusID     | Device modbus address                     | 1             |
+-----------+-------------------------------------------+---------------+
| Period    | Polling frequency (seconds)               | 30            |
+-----------+-------------------------------------------+---------------+

Power Standards Lab pQube
~~~~~~~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.pqube.PQubeModbus``

**Communications**: Modbus/TCP

**Data**: Three phase energy, power, and quality measurements

+--------------+-------------------------------------------+---------------+
| Parameter    | Description                               | Default Value |
+==============+===========================================+===============+
| Address      | Hostname of device (or Modbus/IP gateway) |               |
+--------------+-------------------------------------------+---------------+
| Port         | Port                                      | 502           |
+--------------+-------------------------------------------+---------------+
| SlaveAddress | Device modbus address                     | 1             |
+--------------+-------------------------------------------+---------------+
| BaseRegister | Base register to start reading at         | 7000          |
+--------------+-------------------------------------------+---------------+
| Rate         | Polling frequency (seconds)               | 30            |
+--------------+-------------------------------------------+---------------+

TED 5000
~~~~~~~~

**Module** : ``smap.drivers.ted.Ted5000Driver``

**Communications**: HTTP/XML

+-----------+-----------------------------+---------------------+
| Parameter | Description                 | Default Value       |
+===========+=============================+=====================+
| Address   | URL of device data page     |                     |
+-----------+-----------------------------+---------------------+
| Timezone  | Local timezone of device    | America/Los_Angeles |
+-----------+-----------------------------+---------------------+
| Rate      | Polling frequency (seconds) | 60                  |
+-----------+-----------------------------+---------------------+

UC Berkeley ACme X2
~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.acmex2.acmex2.ACmeX2Driver``

**Communications**: Proprietary UDP

**Data**: Per-device energy and power data.

+-----------+------------------------------+---------------+
| Parameter | Description                  | Default Value |
+===========+==============================+===============+
| Port      | Local IPv6 port to listen on | 702           |
+-----------+------------------------------+---------------+

Obvius Aquisuite
~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.obvius.Driver``

**Communications**: Proprietary XML

+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Parameter  | Description                                                                                                                                                 | Default Value |
+============+=============================================================================================================================================================+===============+
| Url        | URL to download from.  Set to the link returned by the XML download link on the obvius page (e.g. http://10.0.0.1/setup/devicexml.cgi?ADDRESS=58&TYPE=DATA) |               |
+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Username   | HTTP username to authenticate as                                                                                                                            |               |
+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Password   | HTTP password                                                                                                                                               |               |
+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| Period     | Polling frequency (seconds)                                                                                                                                 | 30            |
+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+
| ObviusType | Type of device represented by the xml (see below)                                                                                                           |               |
+------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+

Device maps are stored in ``smap.drivers.obvius.sensordb``.  These map the somewhat opaque mappings present in the Aquisuite XML to nicer sMAP names.  You can pick one from device type on the Aquisuite Page.  Current mappings are:

+-------------------------------------------------+-------------+
| ObviusType                                      | Description |
+=================================================+=============+
| Power Measurement ION 6200                      |             |
+-------------------------------------------------+-------------+
| Power Measurement ION 7300                      |             |
+-------------------------------------------------+-------------+
| Power Measurement ION 7330                      |             |
+-------------------------------------------------+-------------+
| Shark 100                                       |             |
+-------------------------------------------------+-------------+
| Continental Control Systems LLC, WattNode MODBUS|             |
+-------------------------------------------------+-------------+
| Dent Power Scout A                              |             |
+-------------------------------------------------+-------------+
| Veris Full-Data Energy Meter                    |             |
+-------------------------------------------------+-------------+
| SquareD                                         | ?           |
+-------------------------------------------------+-------------+
| GE Enhanced MicroVersaTrip                      |             |
+-------------------------------------------------+-------------+

PG&E GreenButton Downloader
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Module**: ``smap.drivers.pge`` + ``smap.drivers.xslt.XMLDriver``

**Communications**: Web scrape + XML

PG&E makes residential smartmeter data available, but difficult to download through their webpage.  You can combine a mechanized download of the xml with an XSLT transform to create a sMAP source from your PG&E data.

+-----------+---------------------------------------------------------------+----------------------------------+
| Parameter | Description                                                   | Example Value                    |
+===========+===============================================================+==================================+
| Uri       | Set to tell XML driver to use the loader                      | python://smap.drivers.pge.update |
+-----------+---------------------------------------------------------------+----------------------------------+
| Xslt      | Path to XSLT stylesheet.  Included with the sMAP distribution | xslt/greenbutton.xsl             |
+-----------+---------------------------------------------------------------+----------------------------------+
| Period    | Frequency to poll at.  PG&E data updates infrequently.        | 86400                            |
+-----------+---------------------------------------------------------------+----------------------------------+
| Username  | PG&E Login                                                    |                                  |
+-----------+---------------------------------------------------------------+----------------------------------+
| Password  | PG&E Password                                                 |                                  |
+-----------+---------------------------------------------------------------+----------------------------------+
| To        | Optional; date to start download at                           | 1/1/2010                         |
+-----------+---------------------------------------------------------------+----------------------------------+
| From      | Optional; date to end download at                             | 12/31/2012                       |
+-----------+---------------------------------------------------------------+----------------------------------+
| Type      | Optional; type of data feed to use from the result            | "gas" or "electric"              |
+-----------+---------------------------------------------------------------+----------------------------------+

Here's a full example:


.. code-block:: python

  [/pge-gas]
  type = smap.drivers.xml.XMLDriver
  Uri = python://smap.drivers.pge.update
  Xslt = ~/smap-data/xslt/greenbutton.xsl
  Period = 86400
  Username = <username>
  Password = <password>
  # From = 1/1/2010
  # To = 12/31/2012
  Type = gas

Weather
-------


Weather Underground
~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.wunderground.WunderGround``

**Communications**: XML

**Data**: Current conditions for the station.

+-----------+-----------------------------+---------------------------------------------------------------+
| Parameter | Description                 | Default Value                                                 |
+===========+=============================+===============================================================+
| Address   | WUnderground API URL        | http://api.wunderground.com/weatherstation/WXCurrentObXML.asp |
+-----------+-----------------------------+---------------------------------------------------------------+
| ID        | WUnderground station ID     |KCABERKE25                                                     |
+-----------+-----------------------------+---------------------------------------------------------------+
| Rate      | Polling frequency (seconds) | 60                                                            |
+-----------+-----------------------------+---------------------------------------------------------------+
| Period    | Polling frequency (seconds) | 30                                                            |
+-----------+-----------------------------+---------------------------------------------------------------+

NOAA Weather Forecasts
~~~~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.noaaforecast.NOAAForecast``

**Communications**: XML

+-----------+------------------------+---------------+
| Parameter | Description            | Default Value |
+===========+========================+===============+
| lat       | Latitude for forecast  |               |
+-----------+------------------------+---------------+
| lon       | Longitude for forecast |               |
+-----------+------------------------+---------------+

NWS Weather Forecasts
~~~~~~~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.forecastTemp.ForecastTempDriver``

**Communications**: XML

+--------------+------------------------+---------------+
| Parameter    | Description            | Default Value |
+==============+========================+===============+
| Latitude     | Latitude for forecast  |               |
+--------------+------------------------+---------------+
| Longitude    | Longitude for forecast |               |
+--------------+------------------------+---------------+
| LocationName | Location name          |               |
+--------------+------------------------+---------------+

Vaisala WXT520
~~~~~~~~~~~~~~

**Module** : ``smap.drivers.vaisala.VaisalaDriver``

**Communications**: SDI-12 (serial) over IP

+-----------+------------------------------+---------------+
| Parameter | Description                  | Default Value |
+===========+==============================+===============+
| Address   | Hostname of serial/io bridge |               |
+-----------+------------------------------+---------------+
| Port      | port                         |4660           |
+-----------+------------------------------+---------------+

ISO Data
--------


ETCOT
~~~~~

**Module** : ``smap.drivers.ercot.ErcotDriver``

PJM
~~~

**Module** : ``smap.drivers.pjm.PJMDriver``

NYISO
~~~~~

**Module** : ``smap.drivers.nyiso.NYIsoDriver``

MISO
~~~~

**Module** : ``smap.drivers.miso.MIsoDriver``

Washington BPA
~~~~~~~~~~~~~~

**Module** : ``smap.drivers.washingtonbpa.BPADriver``

ISO NE
~~~~~~

**Module**: ``smap.drivers.isone.IsoNEDriver``

CA ISO
~~~~~~

**Module** : ``smap.drivers.caiso.CaIsoDriver``

CA ISO LMP Data
~~~~~~~~~~~~~~~

**Module** : ``smap.drivers.caiso_price.CaIsoPrice``


+-----------+---------------+----------------+
| Parameter | Description   | Default Value  |
+===========+===============+================+
| Location  | LMP Node name | OAKLAND_1_N001 |
+-----------+---------------+----------------+

Other Drivers
-------------


HeatX Flow Meter
~~~~~~~~~~~~~~~~

**Module**: ``smap.drivers.heatx.HeatX``

**Communication**: Modbus over TCP

**Data**: Description from the Central Station Steam Co. Cadillac HEATX BTU Meter

+-----------+------------------------+---------------+
| Parameter | Description            | Default Value |
+===========+========================+===============+
| Host      | Hostname               |               |
+-----------+------------------------+---------------+
| Rate      | Polling rate (seconds) | 20            |
+-----------+------------------------+---------------+

Omega iSeries Steam Gauge
~~~~~~~~~~~~~~~~~~~~~~~~~

**Module**: ``smap.drivers.iseries.IseriesSteam``

**Communication**: Proprietary TCP


+-----------+------------------------+---------------+
| Parameter | Description            | Default Value |
+===========+========================+===============+
| Host      | Hostname               |               |
+-----------+------------------------+---------------+
| Rate      | Polling rate (seconds) | 20            |
+-----------+------------------------+---------------+

Labjack UE9
~~~~~~~~~~~

**Module**: ``smap.drivers.labjack.LabjackDriver``

**Communicate**: Labjack modbus.  Requires updated Labjack firmware.


+------------+---------------------------------------+---------------+
| Parameter  | Description                           | Default Value |
+============+=======================================+===============+
| ConfModule | Python module name with configuration |               |
+------------+---------------------------------------+---------------+

This module is configured through a python module you must write; here is an example (in a file named ``labjackconf.py``:

.. code-block:: python

  BIP_5V = 0x08    # from the datasheet
  
  def temp_cal(x):    # convert an analog reading to celsius
    return x*55.57-273.15+255.37
  
  CONF = {
    'labjack01' : {
      'address' : '10.0.0.1',
      'rate' : 10,
      'channels' : {
      'freezer_bat_temp' : {
        'register' : 0,      # Ain0
        'unit' : 'C',
        'calibrate' : temp_cal,
        'range' : BIP_5V,
      },
      'freezer_air_temp' : {
        'register' : 2,      # Ain1
        'unit' : 'C',
        'calibrate' : lambda x: (x * 100) - 273.15,
        'range' : BIP_5V,
      },
    }
  }

ReadingDB
~~~~~~~~~

**Module**: ``smap.drivers.readingdb.Driver``

**Data**: Statistics from a `readingdb <https://github.com/stevedh/readingdb>`_ database.


+-----------+-------------------------+---------------+
| Parameter | Description             | Default Value |
+===========+=========================+===============+
| Port      | ReadingDB database port | 4242          |
+-----------+-------------------------+---------------+

