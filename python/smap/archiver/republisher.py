"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import copy
import time

from twisted.internet import defer, threads
from twisted.web import resource, server
from twisted.python import log

from autobahn.twisted.websocket import WebSocketServerFactory, \
    WebSocketServerProtocol
from autobahn.twisted.resource import WebSocketResource, \
    HTTPChannelHixie76Aware

from smap.core import SmapException
from smap.server import setResponseCode
from smap.archiver import settings
import smap.util as util
import smap.sjson as json
import queryparse as qp

    
class RepublishEndpoint(object):
    """Generic endpoint for a republish endpoint.  Subclass and
    implement write() (at least).
    """
    # if a client request should fail if republishing on this endpoint
    # fails.
    CLIENT_FAIL = False

    def __init__(self, db, request=None):
        self.db = db
        self.request = request
        self.topics = None      # all topics

    def receive_object(self, key, public):
        """Check if I should receive an object with
        associated key and public setting.
        """
        if 'key' in self.request.args and key in self.request.args['key']:
            return True
        elif not 'private' in self.request.args and public:
            return True
        else:
            return False

    def set_topics(self, topics):
        log.msg("Subscribing republisher to %i streams" % len(topics))
        self.topics = set(topics)

    def update_topics(self, q):
        parser = qp.QueryParser(self.request)
        query = "select distinct uuid where (%s)" % q
        try:
            d = parser.runquery(self.db, query)
        except SmapException, e:
            return defer.fail(e)
        else:
            d.addCallback(self.set_topics)
        return d

    def republish(self, key, public, obj):
        if self.receive_object(key, public):
            if self.topics is None:
                # if they've subscribed to all streams, we can
                # just forward them the object
                self.write(obj)
            else:
                # only include topical data
                custom = dict((k, obj[k]) for k in obj.iterkeys() \
                                  if not 'uuid' in obj[k] or  \
                                  obj[k]['uuid'] in self.topics)
                # don't bother filtering metadata at the moment
                # since it's expensive to construct and mostly
                # won't happen.
                if sum((1 for v in custom.itervalues() if 'uuid' in v)):
                    self.write(custom)

    def notifyFinish(self):
        return self.request.notifyFinish()

    def write(self, obj):
        # override
        raise NotImplementedError()

class HttpRepublishEndpoint(RepublishEndpoint):
    def write(self, obj):
        self.request.write(json.dumps(obj))
        self.request.write("\n\n")

class ReResource(resource.Resource):
    """Provide a "republish resource" -- where you can long-poll to
    listen for new data.
    """
    def __init__(self, db):
        resource.Resource.__init__(self)
        self.clients = set([])
        self.db = db

    def connectionLost(self, client, reason):
        if client in self.clients:
            log.msg("HTTP: removing republish client: " + str(reason.value))
            self.clients.remove(client)

    def add_client(self, client):
        client.notifyFinish().addErrback(lambda x: self.connectionLost(client, x))
        self.clients.add(client)

    def render_GET(self, request):
        client = HttpRepublishEndpoint(self.db, request)
        self.add_client(client)
        # track finishes
        return server.NOT_DONE_YET

    def _fail(self, request, reason):
        setResponseCode(request, reason, 400)
        request.finish()

    def render_POST(self, request):
        client = HttpRepublishEndpoint(self.db, request)
        # track finishes
        d = client.update_topics(request.content.read())
        d.addCallback(lambda _: self.add_client(client))
        d.addErrback(lambda reason: self._fail(request, reason))
        return server.NOT_DONE_YET

    def republish(self, key, public, obj):
        for client in self.clients:
            client.republish(key, public, obj)


class RepublishServerProtocol(WebSocketServerProtocol):
    """WebSocket republish protocol

    Messages sent get interpreted as "where" clauses and change the
    topic set.
    """
    def onConnect(self, request):
        # save the params as args -- this will get used by the query parser
        self.args = request.params

    def onMessage(self, payload, isBinary):
        if self.client: 
            d = self.client.update_topics(payload)
            # disconnect if there's an error running a query
            d.addErrback(lambda reason: self.sendClose())

    def connectionLost(self, *args):
        if self.client:
            self.client.finished.errback(*args)
        WebSocketServerProtocol.connectionLost(self, *args)

class RepublishServerFactory(WebSocketServerFactory):
    """The server factor builds WebSocket republish protocols, and
    adds them to the WebSocket Resource's list of open connections.
    """
    protocol = RepublishServerProtocol 

    def __init__(self, *args, **kwargs):
        self.wsresource = kwargs.pop('wsresource', None)
        WebSocketServerFactory.__init__(self, *args, **kwargs)

    def buildProtocol(self, addr):
        # make a new socket protocol and tell the resource about it
        proto = WebSocketServerFactory.buildProtocol(self, addr)
        self.wsresource.add_client_proto(proto)
        return proto

class WebSocketRepublishEndpoint(RepublishEndpoint):
    """A WebSocket endpoint just overrides a few defaults.

    The default topic set is empty, and objects are sent as framed
    messages rather than json objects separated by newlines.  Also,
    notifyFinish needs to be manually called from connectionLost.
    """
    def __init__(self, *args):
        RepublishEndpoint.__init__(self, *args)
        self.topics = set([])   # start with no topics
        self.finished = defer.Deferred()

    def write(self, obj):
        self.request.sendMessage(json.dumps(obj), False)

    def notifyFinish(self):
        return self.finished

class WebSocketRepublishResource(WebSocketResource):
    """The actual resource for twisted.web integration.

    Builds a factory and sets things up to be republished to WebSocket
    clients.
    """
    def __init__(self, db):
        self.db = db
        self.clients = set([])
        factory = RepublishServerFactory("ws://example.com:8079/wsrepublish", 
                                         debug=False,
                                         wsresource=self)
        WebSocketResource.__init__(self, factory)

    def add_client_proto(self, proto):
        client = WebSocketRepublishEndpoint(self.db, proto)
        proto.client = client
        client.notifyFinish().addErrback(lambda reason: self.connectionLost(client, reason))
        self.clients.add(client)

    def connectionLost(self, client, reason):
        if client in self.clients:
            log.msg("WebSocket: removing republish client: " + str(reason.value))
            self.clients.remove(client)

    def republish(self, key, public, obj):
        for client in self.clients:
            try:
                client.republish(key, public, obj)
            except:
                import traceback
                traceback.print_exc()

def _sanitize_keys(obj):
    # hilariously, the Mongo "database" doesn't support keys
    # starting with '$' or containing '.'
    for k in obj.keys():
        kprime = None
        if k[0] == "$" or k.find(".") != -1:
            kprime = k.replace(".", "_")
            if kprime[0] == "$":
                kprime = kprime[1:]
            obj[kprime] = obj[k]
            del obj[k]

def sterilize_object(obj):
    n = copy.deepcopy(obj)
    for k in obj.iterkeys():
        kprime = k
        if kprime.startswith('$'):
            kprime = k[1:]
        kprime = kprime.replace('.', '__')
        if k != kprime:
            n[kprime] = n[k]
            del n[k]
    return n


class MongoRepublisher(object):
    """Insert sMAP records into a MongoDB collection
    """
    CLIENT_FAIL = True
    
    def __init__(self, db):
        self.db = db
        self.keys = settings.conf['mongo']['keys']

        # optional import -- it will kill the caller if txmongo is unavailable
        import pymongo
        self.mongo = pymongo.MongoClient(settings.conf['mongo']['host'],
                                         settings.conf['mongo']['port'],
                                         socketTimeoutMS=5000,
                                         connectTimeoutMS=30000)

    def republish(self, key, public, obj):
        # check perms
        if (not public and 
            key not in self.keys and 
            not settings.conf['mongo']['publish_all_private']):
            return

        col = self.mongo.smap.republish
        # pymongo mutates the argument ...
        try:
            insert = sterilize_object(obj)
        except:
            import traceback
            traceback.print_exc()
            raise
        insert['__submitted'] = int(time.time() * 1000)
        insert['__key'] = key
        return threads.deferToThread(col.save, insert)


class PostgresEndpoint(RepublishEndpoint):
    def republish(self, key, public, obj):
        insert = sterilize_object(obj)
        insert['__submitted'] = int(time.time() * 1000)
        insert['__key'] = key
        return self.db.runOperation("INSERT INTO republish (key, obj) VALUES (%s, %s)",
                                    (key, json.dumps(insert)))
