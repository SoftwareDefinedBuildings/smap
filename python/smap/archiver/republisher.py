
from twisted.web import resource, server

import smap.util as util

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
    def __init__(self):
        resource.Resource.__init__(self)
        self.listeners = []

    def connectionLost(self, request, reason):
        self.listeners.remove(request)

    def render_GET(self, request):
        # make sure we remove the client when she disconnects
        request.notifyFinish().addErrback(lambda x: self.connectionLost(request, x))
        self.listeners.append(request)
        return server.NOT_DONE_YET

    def republish(self, key, public, obj):
        data = util.json_encode(obj)
        for client in self.listeners:
            if receive_object(client, key, public):
                client.write(data)
                client.write("\n\n")
