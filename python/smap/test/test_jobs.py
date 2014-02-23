from zope.interface import implements
from twisted.internet.defer import Deferred
from twisted.internet.defer import succeed
from twisted.web.iweb import IBodyProducer
from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.protocol import Protocol
from twisted.web.client import Agent
from twisted.web.http_headers import Headers
import json
import sys
import smap.util
import time

class StringProducer(object):
    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

class BeginningPrinter(Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.remaining = 1024 * 10

    def dataReceived(self, bytes):
        if self.remaining:
            display = bytes[:self.remaining]
            print 'Some data received:'
            print display
            self.remaining -= len(display)

    def connectionLost(self, reason):
        print 'Finished receiving body:', reason.getErrorMessage()
        self.finished.callback(None)

def put_json_actuate(url, verb, body_str):
    agent = Agent(reactor)
    body = StringProducer(body_str)
    headers = Headers({'Content-Type': ['application/json']})
    d = agent.request(verb, url, headers, body)
    return d

def validate1(response):
    finished = Deferred()
    response.deliverBody(BeginningPrinter(finished))
    assert response.code == 200
    print 'validate1 okay'
    return finished

def shutdown(response):
    reactor.stop()

if __name__=='__main__':
    val = 1
    wait = float(sys.argv[1])
    start_time = time.time() * 1000 + wait * 1000
    url = 'http://localhost:8080/jobs'
    obj = [
      {'Async': 'True',
       'StartTime': start_time, 
       'Name': 'Job1',
       'Actions': [
          {'State': val, 'Path': '/binary/point0'},
          {'State': abs(val - 1), 'Path': '/binary/point0'},
          {'State': val, 'Path': '/binary/point0'},
          {'State': abs(val - 1), 'Path': '/binary/point0'}
        ]
      },
      {'Async': 'False', 
       'After': 'Job1',
       'Name': 'Job2',
       'Actions': [
          {'State': val, 'Path': '/binary/point0'},
          {'State': abs(val - 1), 'Path': '/binary/point0'},
          {'State': val, 'Path': '/binary/point0'},
          {'State': abs(val - 1), 'Path': '/binary/point0'}
        ]
      }
    ]
    body_str = json.dumps(obj)

    d = put_json_actuate(url, 'PUT', body_str)
    d.addCallback(validate1)
    d.addBoth(shutdown)
    reactor.run() 
