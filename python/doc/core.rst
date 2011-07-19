The Core sMAP Library
=====================

.. py:currentmodule:: smap.core

.. autoclass:: smap.core.SmapInstance

   .. method:: __init__(self, root_uuid, **reporting_args)

      :param root_uuid: a stringified UUID, or a :py:class:`uuid.UUID` instance to be used as the identifier for the root of this sMAP tree.
      :param reporting_args: extra arguments passed to the :py:class:`smap.reporting.Reporting` constructor.

   .. automethod:: start

   .. method:: add_timeseries(path, key, units, **kwargs)

      Simple form: create a :py:class:`Timeseries` and then add it to the :py:class:`SmapInstance`::

        ts = inst.add_timeseries('/sensor', 'my sensor key', 'V', data_type='double')

      :param path: identifier indicating where to add the new resource.
      :param string key: `(optional)` local identifier for this timeseries. if not present uses `path`.
      :param string units: set the ``UnitofMeasure`` field for the :py:class:`Timeseries`.
      :param kwargs: additional arguments for the :py:class:`Timeseries` constructor.
      :rtype: :py:class:`Timeseries` instance.

   .. method:: add_timeseries(path, timeseries)

      Advanced form: add an already-existing :py:class:`Timeseries`.  

      :param path: identifier indicating where the new timeseries will
       be mapped in.  Either a string path starting with '/', a string
       interoperable as a :py:class:`uuid.UUID`, or a
       :py:class:`uuid.UUID` instance.  Must refer to a previously
       created :py:class:`Collection`.
      :param smap.core.Timeseries timeseries: instance to add
      :rtype: :py:class:`Timeseries` instance 

   .. automethod:: smap.core.SmapInstance.add_collection(path[, collection[, replace=False]])

   .. automethod:: smap.core.SmapInstance.get_timeseries

   .. automethod:: smap.core.SmapInstance.get_collection

   .. automethod:: smap.core.SmapInstance.add

   .. automethod:: smap.core.SmapInstance._add

   .. method:: flush()

      Call the :py:meth:`~smap.reporting.Reporting.flush` method
      associated with this instance.

   .. method:: _flush()

      Call the :py:meth:`~smap.reporting.Reporting._flush` method
      associated with this instance.

.. autoclass:: smap.core.Timeseries
   :members: __init__, _add, add

.. autoclass:: smap.core.Collection
   :members: __init__

Accessing Other Properties
--------------------------

Both :py:class:`Collection` and :py:class:`Timeseries` overload
:py:meth:`__setattr__` to validate changes when you access fields
covered by the sMAP schema.  For a :py:class:`Collection`, this means
only ``Metadata``; for a :py:class:`Timeseries`, you have access to
``Metadata``, ``Properties``, and ``Actuator``.

For instance, you can set the Metadata for either type of object like
this::

  ts['Metadata'] = {
      'Instrument' : {
        'Manufacturer' : 'Example Factory, Inc.'
       }
     }

This will cause the Metadata to be validated, so you may get a
:py:class:`smap.core.SmapSchemaException` from this operation.

Reporting
=========

.. autoclass:: smap.reporting.Reporting
   :members: __init__, _flush, flush

Utilities
=========

.. autofunction:: smap.loader.load

.. autofunction:: smap.loader.dump

.. autofunction:: smap.server.run

.. autofunction:: smap.util.periodicCallInThread

.. autofunction:: smap.util.periodicSequentialCall
