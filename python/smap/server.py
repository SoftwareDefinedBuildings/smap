"""Resources for mapping sMAP objects into an HTTP server

When run as the main module, runs a sample server on port 8080
"""

import sys
from twisted.web import resource, server
from twisted.web.resource import NoResource
from twisted.internet import reactor, task, defer
from twisted.python import log

import uuid
import json

import util
import core
import loader
import schema
import smapconf
import actuate

from interface import *

def setResponseCode(request, exception, default):
    if hasattr(exception, 'http_code') and \
            exception.http_code != None:
        request.setResponseCode(exception.http_code)
    else:
        request.setResponseCode(default)

class InstanceResource(resource.Resource):
    """Resource which maps HTTP requests to requests on the sMAP
    instance.
    """
    def __init__(self, inst):
        self.inst = inst
        resource.Resource.__init__(self)

    isLeaf = True
    def render_GET(self, request):
        request.setHeader('Content-type', 'application/json')
        # assemble the results
        try:
            obj = self.inst.lookup(util.join_path(request.postpath))
        except Exception, e:
            setResponseCode(request, exception, 404)
            request.finish()
            return
            
        d = defer.maybeDeferred(core.SmapInstance.render_lookup, request, obj)
        d.addCallback(lambda x: self.send_reply(request, x))
        d.addErrback(lambda x: self.send_error(request, x))
        return server.NOT_DONE_YET

    def render_PUT(self, request):
        request.setHeader('Content-type', 'application/json')
        # you can only PUT actuators
        obj = self.inst.lookup(util.join_path(request.postpath),
                               pred=IActuator.providedBy)
        d = defer.maybeDeferred(core.SmapInstance.render_lookup, request, obj)
        d.addCallback(lambda x: self.send_reply(request, x))
        d.addErrback(lambda x: self.send_error(request, x))
        return server.NOT_DONE_YET


    def send_reply(self, request, obj):
        # the result out using AsyncJSON
        if obj != None:
            d = util.AsyncJSON(obj).startProducing(request)
            d.addBoth(lambda _: request.finish())
        else:
            self.send_error(request, None)

    def send_error(self, request, err):
        if err:
            setResponseCode(request, err.value, 500)
        else:
            request.setResponseCode(500)
        request.write(str(err.value))
        request.finish()

def read_report(self, request, duplicate_error=True):
    """Read a Reporting object sent by the client.  Will validate the
    object and remove extra fields which are not specified in the
    schema.
    """
    obj = schema.filter_fields('Reporting', json.load(request.content))
    if not schema.validate("Reporting", obj):
        raise core.SmapSchemaException("Invalid Reporting object (does not validate)", 400)
    if duplicate_error and self.reports.get_report(obj['uuid']):
        raise core.SmapException("Report instance already exists!", 400)
    return obj

class ReportingInstanceResource(resource.Resource):
    """Resource responsible for dealing with a single reporting instance.
    """
    def __init__(self, reports, inst):
        self.inst = inst
        self.reports = reports
        resource.Resource.__init__(self)

    def render_GET(self, request):
        """The GET verb will return the representation of the
        requested report instance.
        """
        if self.inst:
            request.setHeader('Content-type', 'application/json')
            obj = schema.filter_fields('Reporting', self.inst)
            # print schema.validate('Reporting', obj)
            d = util.AsyncJSON(obj).startProducing(request)
            d.addBoth(lambda _: request.finish())
        else:
            request.setResponseCode(404)
            request.finish()
        return server.NOT_DONE_YET

    def render_PUT(self, request):
        """The PUT verb either stores the request under the requested
        URI, or modifies an existing resource.        
        """
        try:
            request.setHeader('Content-type', 'application/json')
            obj = read_report(self, request, duplicate_error=False)
            if not self.reports.update_report(obj):
                self.reports.add_report(obj)
                request.setResponseCode(201) # created
        except Exception, e:
            setResponseCode(request, e, 400)
            request.setHeader('Content-type', 'text/plain')
            request.write(str(e))
        request.finish()
        return server.NOT_DONE_YET            

    def render_DELETE(self, request):
        """The DELETE verb remove the requested object from the collection"""
        self.reports.del_report(uuid.UUID(request.prepath[-1]))
        request.finish()
        return server.NOT_DONE_YET
            

class ReportingResource(resource.Resource):
    """Resource representing the collection of reports which are installed
    """
    def __init__(self, reports):
        self.reports = reports
        resource.Resource.__init__(self)

    def getChild(self, name, request):
        if name == '':
            return self
        try:
            id = uuid.UUID(name)
            rpt = self.reports.get_report(id)
            return ReportingInstanceResource(self.reports, rpt)
        except:
            return NoResource()

    def render_GET(self, request):
        """In response to a GET, we return a list of the installed reports
        """
        request.setHeader('Content-type', 'application/json')
        obj = {'Contents' : [x['uuid'] for x in self.reports.subscribers]}
        d = util.AsyncJSON(obj).startProducing(request)
        d.addBoth(lambda _: request.finish())
        return server.NOT_DONE_YET

    def render_POST(self, request):
        """A POST can create a new report instance as a subordinate
        resource.
        """
        try:
            request.setHeader('Content-type', 'application/json')
            obj = read_report(self, request)
            self.reports.add_report(obj)
            request.setResponseCode(201)
        except Exception, e:
            request.setHeader('Content-type', 'text/plain')
            setResponseCode(request, e, 400)
            request.write(str(e))
        request.finish()
        return server.NOT_DONE_YET

class RootResource(resource.Resource):
    """Resource representing the root of the sMAP server
    """
    def __init__(self, value=None):
        resource.Resource.__init__(self)
        if value:
            self.value = value
        else:
            self.value = {'Contents' : ['data', 'reports']}

    def getChild(self, name, request):
        if name == '':
            return self
        return resource.Resource.getChild(self, name, request) 

    def render_GET(self, request):
        request.setHeader('Content-type', 'application/json')
        return json.dumps(self.value)

def getSite(inst):
    """Return a service for creating an application
    """
    root = RootResource()
    root.putChild('data', InstanceResource(inst))
    root.putChild('reports', ReportingResource(inst.reports))

    site = server.Site(root)
    return site

def run(inst, port=None):
    """Start the ``twisted`` event loop, with an HTTP server.

:param inst: a :py:class:`~smap.core.SmapInstance` which you want to server.
:param int port: port to run on
:rtype: none; this function does not return
    """
    if not port: port = int(smapconf.SERVER['port'])
    log.startLogging(sys.stdout)
    inst.start()
    reactor.listenTCP(port, getSite(inst))
    reactor.run()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        # create a smap instance.  each instance needs a uuid and it should 
        s = core.SmapInstance('f83c98c0-a8c3-11e0-adf5-0026bb56ec92')

        # add collection -- easy
        # 
        # arg0 : path to collection
        # arg1 : key to generate uuid with, or Collection instance
        s.add_collection("/steve")


        # easy-add -- create a timeseries automatically.  kwargs pass through
        # to the timeseries so you can change the data type, description, etc.
        #
        # the parent must exist and be a collection for this to work.
        #
        # arg0 : path to add at
        # arg1 : either a unique string (key) or a uuid instance
        # arg2 : units
        s.add_timeseries("/sensor0", "sdh", "V")

        # alternative -- add an existing timeseries
        s.add_timeseries("/sensor1", core.Timeseries(s.uuid("sdh2"), "F", buffersz=2))

        # add readings to a timeseries
        # get_timeseries will look up based on either path or uuid
        s.get_timeseries("/sensor0").add(util.now(), 12)
        s.get_timeseries("/sensor0").add(util.now(), 13)

        # you can set timeseries properties by accessing it as a dict.  The
        # changes you make must follow the smap schema and you will get a
        # SmapSchemaException if you try to write an invalid object.
        s.get_timeseries("/sensor0")['Metadata'] = \
            {'Instrument' : {
                'Manufacturer' : "Stephen Dawson-Haggerty"
                },
             'Extra' : {
                'Sucks' : 'Andrew'
                }
             }
        s.get_collection("/")["Metadata"] = {"Extra" : {"foo" : "bar"} }

        # loader.dump(s, 'default.ini')
    else:
        s = loader.load('default.ini')
        loader.dump(s, 'foo.ini')

    counter = 0
    def newreading():
        global counter
        #print '-'*50
        s.get_collection('/')['Metadata']['Location'] = {'Room' : counter}
        s.get_collection('/').dirty_children()
        for i in xrange(0, 1):
#             s.get_timeseries('/sensor0')._add(util.now(), counter)
#             s.get_timeseries('/sensor1')._add(counter)
            s._add('/sensor0', util.now(), counter)
            s._add('/sensor1', counter)
            counter += 1
        # the default flush period is one second, so we'll just rely on that

    t = task.LoopingCall(newreading)
    t.start(10)
    log.startLogging(sys.stdout)
    run(s)
