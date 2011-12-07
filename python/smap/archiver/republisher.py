
from twisted.web import resource, server

import smap.util as util

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


    def republish(self, obj):
        data = util.json_encode(obj)
        for client in self.listeners:
            client.write(data)
            client.write("\n\n")
