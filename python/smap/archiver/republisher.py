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

from twisted.web import resource, server
from twisted.python import log

from smap.core import SmapException
from smap.server import setResponseCode
import smap.util as util
import queryparse as qp

def receive_object(request, key, public):
    """Check if a given client should receive an object with
    associated key and public setting.
    """
    if 'key' in request.args and key in request.args['key']:
        return True
    elif not 'private' in request.args and public:
        return True
    else:
        return False

class ReResource(resource.Resource):
    """Provide a "republish resource" -- where you can long-poll to
    listen for new data.
    """
    def __init__(self, db):
        resource.Resource.__init__(self)
        self.listeners = {}
        self.db = db

    def connectionLost(self, request, reason):
        if request in self.listeners:
            log.msg("removing republish client")
            del self.listeners[request]

    def render_GET(self, request):
        self.add_client(None, request)
        return server.NOT_DONE_YET

    def render_POST(self, request):
        parser = qp.QueryParser(request)
        query = "select distinct uuid where (%s)" % request.content.read() 
        try:
            d = parser.runquery(self.db, query)
        except SmapException, e:
            setResponseCode(request, e, 400)
            return "query: %s\nerror: %s\n" % (query, str(e))
        else:
            d.addCallback(self.add_client, request)
            d.addErrback(lambda _: request.finish())
            return server.NOT_DONE_YET

    def add_client(self, uuids, request):
        # make sure we remove the client when she disconnects
        request.notifyFinish().addErrback(lambda x: self.connectionLost(request, x))
        if uuids != None:
            self.listeners[request] = set(uuids)
            log.msg("adding republish client, %i topics" % len(uuids))
        else:
            self.listeners[request] = None
            log.msg("adding republish client, all topics" )
        return server.NOT_DONE_YET

    def republish(self, key, public, obj):
        data = util.json_encode(obj)
        for client, streams in self.listeners.iteritems():
            if receive_object(client, key, public):
                if streams == None:
                    # if they've subscribed to all streams, we can
                    # just forward them the object
                    client.write("\n\n")
                    client.write(data)
                else:
                    # only include topical data
                    custom = dict((k, obj[k]) for k in obj.iterkeys() \
                                      if not 'uuid' in obj[k] or  \
                                      obj[k]['uuid'] in streams)
                    # don't bother filtering metadata at the moment
                    # since it's expensive to construct and mostly
                    # won't happen.
                    if sum((1 for v in custom.itervalues() if 'uuid' in v)):
                        client.write(util.json_encode(custom))
                        client.write("\n\n")
                    
