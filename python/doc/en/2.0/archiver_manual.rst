.. _archiver-install-manual:

First steps
~~~~~~~~~~~

In order to set up the archiver, you'll need to install and configure:

* readingdb (time-series database)
* postgresql (metadata storage)
* powerdb2 (administration front-end)
* archiver (the actual service)

To get started, create a new directory for all of the sources::

  $ mkdir ~/sources
  $ cd ~/sources

These instructions apply for Ubuntu 11.10 and may require translation
for your system. For the purposes of this guide, I assume you follow
the instruction linearly; if you do them out-of-order, you may have to
hunt through earlier sections to satisfy all the dependencies.

Before getting started, you'll want to configure monit.  First,
install it using ``sudo apt-get install monit``.  Then, edit
``/etc/monit/monitrc`` and make sure the following is uncommented::

  set httpd port 2812 and
      use address localhost
      allow localhost

Then do a ``sudo /etc/init.d/monit restart``.

ReadingDB
~~~~~~~~~

ReadingDB and its dependencies can be installed easily with Debian
packages. If you are on Ubuntu oneiric (11.10) or precise (12.04), 
you can add our package repository using::

  $ sudo add-apt-repository ppa:stevedh/smap
  $ sudo apt-get update

The archive is here (`<https://launchpad.net/~stevedh/+archive/smap>`_).

You can then install readingdb using apt::
  
  $ sudo apt-get install readingdb readingdb-python

If this worked properly you can now skip to the PostgreSQL section.
If not, you can install readingdb's dependencies and 
build it from source. Note that this is significantly trickier, so
the above method is recommended if it's available.

To begin the manual installation, install readingdb's build 
dependencies (check the `README <https://github.com/stevedh/readingdb>`_).
On Ubuntu 11::

  $ sudo apt-get install libdb4.8 libdb4.8-dev libprotobuf-c0   \
       libprotobuf-c0-dev protobuf-c-compiler zlib1g zlib1g-dev \
       build-essential autoconf libtool python python-dev       \
       python-numpy swig check 

Next, checkout readingdb::

  $ git clone git://github.com/stevedh/readingdb.git

Then, configure and build the sources::

  # build the main source
  $ autoreconf --install
  $ ./configure --prefix=/
  $ make
  $ sudo make install
  # build the python bindings
  $ cd iface_bin
  $ make
  $ sudo make install

Finally, start the service.  A service config file is automatically created in `/etc/monit/conf.d`::

  $ sudo monit reload
  $ sudo monit start readingdb

At this point, you can check to make sure it got started using ``ps
-eaf|grep readingdb``.  The data is put in ``/var/lib/readingdb`` by
default.

PostgreSQL
~~~~~~~~~~

We'll need to install and configure postgres before installing the
rest of the archiver.  Start by installing the daemon and some client
bindings::

  $ apt-get install postgresql postgresql-contrib python-psycopg2

Next, log in and create a user for the archiver to use (you should
change the password).  We also need to set up a few extensions it will
use::

  root@box$ sudo su postgres
  postgres@box$ psql
  postgres=# CREATE USER archiver WITH PASSWORD 'password';
  postgres=# CREATE DATABASE archiver WITH OWNER archiver;
  postgres=# \d
  postgres@box$ psql archiver 
  postgres=# CREATE EXTENSION hstore;
  postgres=# \d
  postgres@box$ exit

Okay, that was unpleasant.  But we're ready to install the web frontend now!

powerdb2
~~~~~~~~

To get started, powerdb has several dependencies you can install::

  $ sudo apt-get install subversion python-django
  $ sudo pip install avro python-dateutil django-piston

Next, we need to check out the powerdb2 project::

  $ cd ~/sources
  $ svn checkout http://smap-data.googlecode.com/svn/branches/powerdb2
  $ cd powerdb2/

Now, edit ``settings.py`` and change the field with the database
password to be whatever you just created.  If you have any other
site-specific database options, you should also edit them now.  Once
that works, you can go ahead and create the database tables::

  $ python manage.py syncdb

You should be prompted to create an admin user during this process (if
not, do so with `python manage.py createsuperuser`).  Once you've gotten
this far, you can run the plotter inside the developement server::

  $ python manage.py runserver 

You can then go to http://localhost:8000 in your browser and log in
using your super user password.  You'll probably want to create a new
API key for later, by going to
http://localhost:8000/admin/smap/subscription/add.

This will do for now; in the future, you might want to run the site
inside of apache using `mod_python` and `mod_wsgi`.

The Archiver
~~~~~~~~~~~~

The final step is to configure the actual archiver process.  Again,
start with dependencies.  The archiver requires numpy and scipy for
some of the operators.  Several of the powerdb2 dependences are also
required::

  $ cd ~/sources
  $ sudo apt-get install python-twisted python-scipy
  $ sudo pip install ply
  $ svn checkout http://smap-data.googlecode.com/svn/trunk smap-data-read-only

You can actually install pretty much everything now::

  $ cd smap-data-read-only/python
  $ sudo python setup.py install

If it all went well, you'll be able to run `twistd` with no arguments;
it prints out a list of plugins at the end and you should see both
`smap` and `smap-archiver` in there.

Copy some files into `/etc/` to complete the setup::

  $ sudo mkdir /etc/smap
  $ sudo cp conf/archiver.ini /etc/smap
  $ sudo cp monit/archiver /etc/monit/conf.d

You should edit `archiver.ini` to include the postgres password, as well
as any other non-default configuration (if you're following these
instructions exactly, there shouldn't be anything else to do).

Finally, you can reload monit and start the archiver::

  $ monit reload
  $ monit start archiver
