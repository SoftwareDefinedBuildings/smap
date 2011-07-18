
from twisted.web import resource, server
from twisted.internet import reactor

import uuid

import util as util
import core as core

s = core.SmapServer(uuid.uuid1())
s.add_collection("/steve", core.Collection(s.uuid("steve")))
s.add_timeseries("/sensor0", core.Timeseries(s.uuid("sdh"), "V", buffersz=2))
s.get_timeseries("/sensor0").add(util.now(), 12)
s.get_timeseries("/sensor0").add(util.now(), 13)
s.get_timeseries("/sensor0")['Metadata'] = {'Instrument' : {
        'Manufacturer' : "Stephen Dawson-Haggerty"},
                                            'Extra' : {
        'Sucks:' : 'Andrew'
                                            }
                                            }
s.get_collection("/")["Metadata"] = {"Extra" : {"foo" : "bar"} }
print "IMPORT"

class SmapResource(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        obj = s.lookup(request.path)
        util.dump_json(obj, request)
        request.finish()
        return server.NOT_DONE_YET


if __name__ == '__main__':
    r = SmapResource()
    reactor.listenTCP(8080, server.Site(r))
    reactor.run()
