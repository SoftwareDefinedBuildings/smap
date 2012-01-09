
from twisted.internet import reactor
from twisted.web import resource, server
from twisted.web.resource import NoResource
from twisted.python import log

from smap import subscriber, reporting
from smap.server import RootResource
import smap.util as util
from smap.archiver import settings, data, api, republisher


class DataResource(resource.Resource):
    """This resource manages the functionality of the add/ resource,
    which is how data is inserted into the system.  Data is POSTed to
    /add/[api key]; this resource checks that it is a valid key and
    then inserts it into the postgres and readingdb databases.
    """
    def __init__(self, db, republisher):
        self.db = db
        self.republisher = republisher
        self.data = data.SmapData(db)
        resource.Resource.__init__(self)

    def _add_data(self, subid, obj):
        """Add the data using the data interface"""
        if len(obj) == 0: return True
        return self.data.add(subid, obj)

    def _check_subscriber(self, request, subid):
        """Check that there was an API key, and republish"""
        if len(subid) == 1:
            # send the object to the republisher
            public = subid[0][1]
            subid = subid[0][0]
            obj = util.json_decode(request.content.read())
            self.republisher.republish(request.prepath[-1], public, obj)
            reporting.push_metadata(obj)
            return subid, obj
        else:
            request.setResponseCode(404)
            request.finish()
        return server.NOT_DONE_YET

    def getChild(self, name, request):
        return self

    def render_POST(self, request):
        """Handle new data"""

        # first check if the api key is valid
        d = self.db.runQuery("SELECT id, public FROM subscription WHERE key = %s", 
                             (request.prepath[-1],))
        d.addCallback(lambda x: self._check_subscriber(request, x))

        # if so, add the data
        d.addCallback(lambda (subid, obj): self._add_data(subid, obj))
        def add_success(x):
            if not x:
                request.setResponseCode(500)
            request.finish()
        def add_error(x):
            # return a 500 so the sMAP server can hold onto the data
            # until things can be fixed.
            request.setResponseCode(500)
            request.finish()

        # and finish the request
        d.addCallback(add_success)
        d.addErrback(add_error)
        return server.NOT_DONE_YET

def getSite(db):
    """Get the twisted site for smap-archiver"""
    root = RootResource(value={'Contents': ['add', 'api', 'republish']})
    repub = republisher.ReResource(db)
    root.putChild('add', DataResource(db, repub))
    root.putChild('api', api.Api(db))
    root.putChild('republish', repub)
    return server.Site(root)

