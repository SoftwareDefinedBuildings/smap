Installation
============

The three core pieces of sMAP (sources, the archiver, and powerdb2)
can be installed separately and in different places, depending on the
needs of the user.  For instance, the archiver is frequently placed in a
datacenter or on a machine with sufficient resources, whereas sMAP
sources are placed on low-power embedded devices close to the
instrumentation they access.

.. _library-install:

sMAP Library Installation
-------------------------

There are numerous ways to get the sMAP library.  The library contains
everything you need to create sources; installing the archiver and
powerdb2 requires additional setup.  

pip
~~~

If you have distutils installed, sMAP is available along with its
dependencies from the `PyPI <http://pypi.python.org/pypi/Smap>`_.  Installing
it should be as easy as::

 pip install smap

To install from svn, have a look at the dependencies below.

Dependencies
~~~~~~~~~~~~

* `python 2.6, 2.7 <http://www.python.org>`_
* `twisted >= 11 <http://www.twistedmatrix.com>`_
* `zope.interface <http://pypi.python.org/pypi/zope.interface>`_
* `avro <http://avro.apache.org/releases.html>`_
* `configobj 4 <https://pypi.python.org/pypi/configobj/>`_
* `python-dateutil <http://pypi.python.org/pypi/python-dateutil>`_

For the Cal ISO driver used in the tutorial, you also need:

* `BeautifulSoup <http://www.crummy.com/software/BeautifulSoup/>`_

If you wish to send data using SSL, you also need:

* `pyOpenSSL <https://launchpad.net/pyopenssl>`_ (optional)

For high-performance data downloading, you can include:

* ``pycURL``

On debian, you can install these with apt::

 $ apt-get install python python-zopeinterface python-twisted python-dateutil python-beautifulsoup

You can then install configobj and avro using pip.

Install from Source
~~~~~~~~~~~~~~~~~~~

Once the dependencies are installed, you can download and install the
smap source.  Right now we recommend that you use the svn version
following the instructions `here
<http://code.google.com/p/smap-data/source/checkout>`_::

 $ svn checkout http://smap-data.googlecode.com/svn/trunk/ smap-data-read-only
 $ cd smap-data-read-only/python
 $ sudo python setup.py install

sMAP installs a few tools as well as a plugin for ``twistd``, a
service manager for twisted.  If you run ``twistd`` with no arguments, you should see the option for running a sMAP server::

 $ twistd
 ...
    smap             A sMAP server
 ...

.. include:: archiver_install.rst
