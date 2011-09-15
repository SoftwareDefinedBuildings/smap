Installation
============

Dependencies
------------

* `python 2.6, 2.7 <http://www.python.org>`_
* `twisted 11 <http://www.twistedmatrix.com>`_
* `zope.interface <http://pypi.python.org/pypi/zope.interface>`_
* `avro <http://avro.apache.org/releases.html>`_

For the Cal ISO driver used in the tutorial, you also need:

* `dateutil <http://pypi.python.org/pypi/python-dateutil>`_
* `BeautifulSoup <http://www.crummy.com/software/BeautifulSoup/>`_

On debian, you can install nearly all of this with::

 $ apt-get install python python-zopeinterface python-twisted python-dateutil python-beautifulsoup

Unfortunately, you must still install avro by hand.

Install
-------

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