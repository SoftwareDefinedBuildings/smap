.. _archiver-install:

Archiver and frontend installation
----------------------------------

.. include:: archiver_manual.rst

Resources
~~~~~~~~~

* One installation option is an experimental `vm image
  <http://jackalope.cs.berkeley.edu/~stevedh/Ubuntu-11.10-smap-444.ova>`_
  [1.6G].  It has Ubuntu 11.10 installed; the username/password is
  ``ubuntu/reverse``, and the login for the sMAP admin page is
  ``root/reverse``.

Next Steps
~~~~~~~~~~

If you've gotten this far, you have the entire backend running.
You'll want to explore and extend this in a couple of different ways.
For instance, you could

* Start adding data, perhaps by following the :ref:`driver-tutorial`.
* Explore making :ref:`ArchiverQuery` queries against your backend.
  Just fire up ``smap-query -u http://localhost:8079/api/query`` on
  your machine.
* Check out how to write your own sMAP source in the :ref:`driver-tutorial`.
* Build your own dashboard or other frontend using **powerdb2** as a template
