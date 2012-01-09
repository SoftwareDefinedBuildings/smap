
from twisted.web import resource, server

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
    def __init__(self, db):
        resource.Resource.__init__(self)
        self.listeners = {}
        self.db = db

    def connectionLost(self, request, reason):
        if request in self.listeners:
            del self.listeners[request]

    def render_GET(self, request):
        self.add_client(None, request)
        return server.NOT_DONE_YET

    def render_POST(self, request):
        parser = qp.QueryParser(request)
        query = "select distinct uuid where (%s)" % request.content.read() 
        try:
            print query
            d = parser.runquery(self.db, query)
        except SmapException, e:
            setResponseCode(request, error, 400)
            return str(e)
        else:
            d.addCallback(self.add_client, request)

            def eb(e):
                print e
                request.finish()
            d.addErrback(eb)
            return server.NOT_DONE_YET

    def add_client(self, uuids, request):
        # make sure we remove the client when she disconnects
        request.notifyFinish().addErrback(lambda x: self.connectionLost(request, x))
        if uuids != None:
            self.listeners[request] = set(uuids)
            print "adding republish client, %i topics" % len(uuids)
        else:
            self.listeners[request] = None
            print "adding republish client, all topics" 
        return server.NOT_DONE_YET

    def republish(self, key, public, obj):
        data = util.json_encode(obj)
        for client, streams in self.listeners.iteritems():
            if receive_object(client, key, public):
                if streams == None:
                    # if they've subscribed to all streams, we can
                    # just forward them the object
                    client.write(data)
                else:
                    # only include topical data
                    custom = dict((k, obj[k]) for k in obj.iterkeys() \
                                      if not 'uuid' in obj[k] or  \
                                      obj[k]['uuid'] in streams)
                    # don't bother filtering metadata at the moment
                    # since it's expensive to construct and mostly
                    # won't happen.
                    client.write(util.json_encode(custom))
                client.write("\n\n")
                    
