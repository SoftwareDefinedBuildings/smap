The sMAP Archiver Interface
===========================

.. py:currentmodule:: smap.archiver.client

The sMAP archiver is a streaming storage manager which adds tools for
storing time-series data from sMAP sources, and accessing both
historical and real-time data.  It may be used as an interface for
developing applications which access sMAP data, or retrieve data for
offline analysis.

The archiver API is available over HTTP.  To provide easier access,
the `py:class:client` provides python bindings for this API.  Using
this client interface may be faster than using the HTTP API directly,
because it attempts to conduct multiple parallel downloads using HTTP
1.1 sessions, if pycurl bindings are available.

.. autoclass:: smap.archiver.client.SmapClient

  .. automethod:: __init__

  .. automethod:: query

  .. automethod:: tags

  .. automethod:: data_uuid

  .. automethod:: data

.. autoclass:: smap.archiver.client.RepublishClient

  .. automethod:: __init__

  .. automethod:: connect

  .. automethod:: close