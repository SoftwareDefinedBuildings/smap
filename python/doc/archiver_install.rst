.. _archiver-install:

Archiver and frontend installation
----------------------------------

The recommended way to install the archiver is using Debian packages.
The process has been tested on Ubuntu 11.10 and 12.04, although it
will probably work on other similar distributions.  It contains stable
version of the sMAP system.  If an Ubuntu machine is not available, or
you wish to install the system manually, please read
:ref:`archiver-install-manual`

Resources
~~~~~~~~~

* You can see a screencast of this process `here
  <http://windows.lbl.gov/smap/video/smap_installation.mov>`_,
  contributed by Christian Kohler.

* Another installation option is an experimental `vm image
  <http://jackalope.cs.berkeley.edu/~stevedh/Ubuntu-11.10-smap-444.ova>`_
  [1.6G].  It has Ubuntu 11.10 installed; the username/password is
  ``ubuntu/reverse``, and the login for the sMAP admin page is
  ``root/reverse``.

Automated Install
~~~~~~~~~~~~~~~~~

If you are on Ubuntu oneiric (11.10) or precise (12.04), you can add our package repository using::

  $ sudo add-apt-repository ppa:stevedh/smap
  $ sudo apt-get update

The archive is here (`<https://launchpad.net/~stevedh/+archive/smap>`_).

You can then install the entire system using apt::

  $ sudo apt-get install readingdb readingdb-python python-smap powerdb2 monit

You will be prompted to create a django admin account during this installation.

After installation completes, you should tweak ``monit``'s configuration: open ``/etc/monit/monitrc``, and ensure the following three lines are uncommented::

  set httpd port 2812 and
      use address localhost
      allow localhost 

After doing this, restart monit: ``sudo /etc/init.d/monit restart``.

The Debian packages will automatically setup and start all required
services, with the exception of the web frontend.  They install an
apache site called `powerdb2`; if you are not running anything else on
your server you can enable it by doing the following; if you have
multiple sites you may want to edit the site to add a ``ServerName`` or
``ServerAlias``::

  $ sudo a2dissite default
  $ sudo a2ensite powerdb2
  $ sudo service apache2 reload

Following this step, you should be able to visit "http://localhost" in
your browser and see the front end.  You will also have access to
"http://localhost/admin", through which you can manage API keys and
the trees visible in the plotting front-end.

Next Steps
~~~~~~~~~~

If you've gotten this far, you have the entire backend running.
You'll want to explore and extend this in a couple of different ways.
For instance, you could

* Explore making :ref:`ArchiverQuery` queries against your backend.
  Just fire up ``smap-query -u http://localhost:8079/api/query`` on
  your machine.
* Check out how to write your own sMAP source in the :ref:`driver-tutorial`.
* Build your own dashboard or other frontend using **powerdb2** as a template