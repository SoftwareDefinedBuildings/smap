
import json

from zope.interface import implements
from twisted.python.util import println
from twisted.python import log
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.internet.defer import succeed, inlineCallbacks, DeferredSemaphore, Deferred
from twisted.web.iweb import IBodyProducer, UNKNOWN_LENGTH
from twisted.web.client import Agent, HTTPConnectionPool, _HTTP11ClientFactory
from twisted.web.http_headers import Headers
from twisted.internet.task import LoopingCall

from smap.util import FixedSizeList

class PlotlyStreamProducer(object):
    """Implements a producer that copies from a buffer to a plot.ly
    connection.
    """
    implements(IBodyProducer)
    length = UNKNOWN_LENGTH

    def __init__(self, buffer, start_callback=None):
        self.buffer = buffer
        self._done = False
        self._flush = DeferredSemaphore(1)
        self._waiter = DeferredSemaphore(1)
        self._flush.acquire()
        self._started = start_callback
        self._keepalive = LoopingCall(self._send_keepalive)

    @inlineCallbacks
    def startProducing(self, consumer):
        self._keepalive.start(60)
        self._started.callback(None)
        while True:
            # if paused, this will block
            yield self._waiter.acquire()
            while len(self.buffer):
                v = self.buffer.pop(0)
                if v is not None:
                    consumer.write(json.dumps(v))
                consumer.write("\n")
            yield self._waiter.release()

            if self._done: 
                return
            yield self._flush.acquire()

    def pauseProducing(self):
        return self._waiter.acquire()

    def resumeProducing(self):
        return self._waiter.release()

    def stopProducing(self):
        self._done = True
        if self._keepalive.running:
            self._keepalive.stop()

    def _send_keepalive(self):
        self.buffer.append(None)
        self.flush()

    def flush(self):
        if self._flush.tokens == 0:
            self._flush.release()


class PlotlyStream(object):
    """Class representing a publisher of a single plot.ly stream.

    A PlotlyStream should be instantiated with the token of a plot.ly
    stream id.  You can optionally change the URL the data is sent to,
    or the buffer size.  The buffer is a fixed-sized list of data
    which has not been sent to plot.ly yet.  If you push multiple
    readings inside of a tight loop, you should make sure the buffer
    is large enough; however, since plot.ly requests that you do not
    generate data more than once every 50ms, it most likely does not
    need to be large.

    When the first reading is added, the client will open an HTTP
    connection using plot.ly streaming protocol, and hold that
    connection open until the process exists, sending keepalives every
    60 seconds.  The client class implements a reconnection state
    machine with appropriate backoffs; however, if the connection
    fails, only the data in the fixed size buffer will be sent when a
    reconnection becomes possible.

    To use, simply make a stream, and call add() to add data:

    s = PlotlyStream('5pzopc6cl6')
    s.add(time.time() * 1000, 10)
    # add more data in callbacks, whatever.

    If publishing timeseries, it appears that timestamps should be in
    units of UTC milliseconds.
    """
    def __init__(self, token, uri="http://stream.plot.ly", buffersz=5):
        """Create a plotly stream publisher with a particular stream id"""
        self.streamid = token
        self._connected = False
        self._uri = uri
        self._buffer = FixedSizeList(buffersz)
        self._reset_connection_stats(None)

    def __getstate__(self):
        return (self.streamid, self._uri, self._buffer.size)

    def __setstate(self, *state):
        self.__init__(*state)

    def add(self, x, y, extra=None):
        """Publish a particular reading to plot.ly"""
        val = {'x': x, 'y': y}
        if extra: val.update(extra)
        self._buffer.append(val)
        self._flush()

    def _flush(self):
        if not self._connected:
            d = self._connect()
            d.addCallback(lambda _: self._flush())
        elif hasattr(self, '_producer'):
            self._producer.flush()

    def _connect(self):
        started = Deferred()
        self._connected = True
        if self._stats['http_failures']:
            timeout = min(320, 5 ** self._stats['http_failures'])
        elif self._stats['tcp_failures']:
            timeout = min(16, 0.25 * self._stats['tcp_failures'])
        else:
            timeout = 0
        log.msg("PlotlyStream (%s - %s): retrying connection in %.02f" % (
                self._uri, self.streamid, timeout))
        reactor.callLater(timeout, self._attempt, started)
        return started

    def _attempt(self, started):
        finished = Deferred()
        started.addCallback(self._reset_connection_stats)
        self._producer = PlotlyStreamProducer(self._buffer, start_callback=started)
        agent = Agent(reactor) 
        d = agent.request('POST',
                          self._uri,
                          Headers({'User-Agent': ['twplotly'],
                                   'Content-Type': ['application/json'],
                                   'plotly-streamtoken': [self.streamid]}),
                          self._producer)
        d.addCallback(self._http_failure)
        d.addErrback(self._tcp_failure)
        return d

    def _reset_connection_stats(self, result):
        self._stats = {
            'http_failures': 0,
            'tcp_failures': 0
            }
        return result

    def _http_failure(self, resp):
        log.msg("PlotlyStream (%s - %s): HTTP disconnection: %i" % (
                self._uri, self.streamid, resp.code))
        if resp.code > 200:
            self._stats['http_failures'] += 1
        self._connected = False
        self._producer.stopProducing()

    def _tcp_failure(self, err):
        log.msg("PlotlyStream (%s - %s): TCP disconnection: %s" % (
                self._uri, self.streamid, str(err.value)))
        self._stats['tcp_failures'] += 1
        self._connected = False
        self._producer.stopProducing()

                                                
if __name__ == '__main__':
    import time, sys

    import plotly.plotly as py
    import plotly.tools as tls
    from plotly.graph_objs import Stream, Scatter, Data, Layout, Figure
    
    log.startLogging(sys.stdout)

    # generate this in the settings of your plot.ly account
    my_stream_id = '5pzopc6cl6'

    # you might have to call this to set up the plot if you haven't
    # already
    def make_plot():
        tls.set_credentials_file(stream_ids=[my_stream_id])
        my_stream = Stream(token=my_stream_id, maxpoints=100)
        my_data = Data([Scatter(x=[], y=[],
                                mode="lines+markers",
                                stream=my_stream)])
        my_layout = Layout(title="Time Series")
        my_fig = Figure(data=my_data, layout=my_layout)
        unique_url = py.plot(my_fig, filename="demo_smap_streaming")

    producer = PlotlyStream(token=my_stream_id) 

    # periodically push new values
    val = 0
    def new():
        global val
        val += 1
        producer.add(time.time() * 1000, val)
        producer.add((time.time() + 0.5) * 1000, val + 0.5)

    LoopingCall(new).start(0.5)
    reactor.run()
