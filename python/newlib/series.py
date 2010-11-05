
import time
import logging
import threading
import Queue
import numpy as np

try:
    import cjson as json
except ImportError:
    import json

import SmapSubscription
import SmapPoint
import util

REPO_ROOT='www.openbms.org'

class SmapSeries:
    """A class representing the timeseries from a single sMAP source.

    Instantiate using the stream identifier obtained from the sMAP
    management backend.  These identifiers look like email addresses
    or XMPP handles; for instance, "10@jackalope.cs.berkeley.edu/django".

    Once so instantiated, historical and real-time data are available
    using this object.  For stored data, there may be multiple series
    available, since some storage engines materialize subsampled or
    realigned data.  For performance reasons, it is often desirable to
    select less then the full resolution when accessing data.

    Because the real-time data uses the sMAP reporing facility, it
    will not work if you are NAT-ed.
    """
    def __init__(self, identifier):
        """Instantiate a SmapSeries, and load metadata from the storage engine.

        @identifier an email-address-like string specifying the stream in question.

        Raises ValueError if metadata for the stream could no be loaded.
        """
        self.identifier = identifier.split('@')
        self.log = logging.getLogger('SmapSeries')
        self.meta = util.http_load('http://' + self.identifier[1] +
                                   '/smap/meta/' + self.identifier[0])
        if self.meta == None:
            raise ValueError("Could not load data associated with sMAP stream: " +
                             identifier)
        
    def _get_smapsubscription(self):
        """Return a reference to the initialized global subscription
        manager -- there's only one of these per python program.
        """
        global smap_subscription
        try:
            smap_subscription
        except NameError:
            self.log.info('Starting sMAP subscription service')
            smap_subscription = SmapSubscription.SmapSubscription()
            smap_subscription.start()
        return smap_subscription

    def _calibrate(self, value):
        if value == None:
            return None
        else:
            return (float(value) * self.meta['Multiplier']) / self.meta['Divisor']

    def realtime(self):
        """A generator for accessing real-time data.
        
        The iterator returned will block if called an no new data is
        available.  To access new data, you would typically do:

        stream = SmapStream(ident)
        for r in stream.realtime():
           print r.time, r.value

        The values are returned in the form of SmapPoint.Reading named tuples.
        """
        smap_subscription = self._get_smapsubscription()
        q = Queue.Queue()
        smap_subscription.subscribe(self.meta['SmapLocation'],
                                    '~/' + self.meta['Path'] + '/reading',
                                    lambda k,d: q.put(d))
        while True:
            # SDH : without a timeout, python will not handle an
            # incomming KeyboardInterupt correctly.  Seems related to
            # Issue8844 but for 2.6.
            data = q.get(True, timeout=0xffffffff)
            yield SmapPoint.Reading(time=data['ReadingTime'],
                                    value=self._calibrate(data['Reading']),
                                    min=self._calibrate(data.get('Min')),
                                    max=self._calibrate(data.get('Max')))

    def loadrange(self, start, end, rate=None, timeout=240):
        """Load data from this stream into a numpy.arpydoray, with all data
        falling between start and end.  The series will be truncated to the
           most data which falls within that range.

           @start unix timestamp of requested start of range
           @end unix timestamp of requested end of range
           @rate may be either 
               (a) None: the highest-frequency data will be fetched, 
               (b) a specific rate in seconds.  data will be returned
                 if there is an underlying subsampled stream at that
                 rate, or
               (c) a tuple (min, max) of acceptable rates.  The
                 lowest-resolution data within that range will be
                 selected; one of the endpoints must not be None.
            @timeout how long to wait on the server; fetching lots of
               data can be slow
        """
        query = { 'start' : start, 'end' : end }
        url = 'http://' + self.identifier[1] + '/smap/data/' + \
              self.identifier[0] + "?start=" + str(int(start)) + \
              "&end=" + str(int(end))
        start_time = time.time()
        data = util.http_load(url, timeout=timeout)
        self.log.debug("data load took %.3fs" % (time.time() - start_time))
        if data != None:
            return np.array(data)
        else:
            return None
        

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    s = SmapSeries(str(34) + '@' + REPO_ROOT)

    d = s.loadrange(time.time() - 3600, time.time())


    print d
    # print d[-1,0] - d[0,0]
#     for d in s.realtime():
#         print d
