"""Functions and classes for running an HTTP server providing sMAP
resources.

To create the simplest SMAP service, first instantiate a SmapInstance
object.  Then start a server using this module.  See the SmapInstance
documentation for more information on adding data.

    data = {
        '0' : {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',multiplier=None,
                                                              divisor=None,type='electric',
                                                              ctype='sensor'),
                                         SmapPoint.Parameter(interval=1, time='second')) } }

    inst = SmapInstance.SmapInstance(data)

    SmapHttp.start_server(inst, port=8080)

    By default, this will block and run in the foreground.  If you
    want it to spawn a daemon thread, you can use the background
    keyword argument:
    
    SmapHttp.start_server.SmapInstance(data, background=True, port=8080)

"""

import sys
import json
import urlparse
import socket
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn, BaseRequestHandler
import threading
import thread
import ssl
import re

import logging
import smaplog
import SmapInstance
import Reporting

if sys.version_info < (2,6,6):
    print >>sys.stderr, "WARNING: you are using a python less than 2.6.6.  SSL support will be broken due to issue #5238!"

class SmapHttpException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "SmapHttpException code: " + str(self.code)

def _recursive_get(request, path, query, root):
    if isinstance(root, dict):
        if len(path) == 0:
            return root.keys()
        if path[0] == '*':
            rv = {}
            for k,v in root.iteritems():
                rv[k] = _recursive_get(request, path[1:], query, v)
                if rv[k] == None or rv[k] == {}:
                    del rv[k]
            return rv
        elif root.has_key(path[0]):
            return _recursive_get(request, path[1:], query, root[path[0]])
        else:
            raise SmapHttpException(404)
    elif hasattr(root, 'http_get'):
        return root.http_get(request, path, query=query)
    else:
        # invalid method
        # TODO : the spec says we need to specify an "allow" line of
        # accepted methods
        raise Exception("Invalid HTTP dict!")

def recursive_get(request, resource, root):
    """
Get an object recursively based on a resource request.
Supports the "star" (*) syntax for requesting a collection

@resource a resource name, as in one returned by urlparse.urlsplit
@root a dict to fetch the resource against.  The objects at the leaves
    must have an http_get method, which will be called to generate the 
    json response.

throws: SmapHttpException if there is a server-type error; includes an http code
        Exception: if the dict object doesn't have a proper object at a leaf
        """
    global smap_lock, smap_root
    path = Reporting.path_segments(resource.path)
    smap_lock.acquire()
    try:
        if len(path) > 0 and path[0] == '~':
            # relative path
            return _recursive_get(request, path[1:], resource.query, root)
        else:
            # absolute path
            return _recursive_get(request, path, resource.query, smap_root)
    except Exception, e:
        logging.warn("Exception in recursive get: " + str(e) +
                     "\npath: '" + resource.path + "' query: '" +
                     resource.query + "'")
        if isinstance(e, SmapHttpException):
            raise e
        else:
            print e
            raise SmapHttpException(500)
    finally:
        smap_lock.release()

def _recursive_method(request, method, path, root, *extra):
    if isinstance(root, dict) and len(path) > 0:
        if root.has_key(path[0]):
            return _recursive_method(request, method, path[1:], root[path[0]], *extra)
    elif hasattr(root, method):
        fn = getattr(root, method)
        return fn(request, path, *extra)
    else:
        raise SmapHttpException(405)

def recursive_method(request, method, resource, root, *extra):
    global smap_lock
    path = Reporting.path_segments(resource.path)
    try:
        smap_lock.acquire()
        return _recursive_method(request, method, path, root, resource.query, *extra)
    finally:
        smap_lock.release()

def lock():
    global smap_lock
    return smap_lock.acquire()

def release():
    global smap_lock
    return smap_lock.release()

def smap_server_init():
    global smap_lock
    try:
        smap_lock
    except NameError:
        smap_lock = threading.RLock()
            

def start_instances(place):
    if isinstance(place, SmapInstance.SmapInstance):
        if not place.is_alive():
            place.start()
    elif isinstance(place, dict):
        for subplace in place.itervalues():
            start_instances(subplace)


class SmapHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global smap_root
        path = re.sub('/+', '/', self.path)
        resource = urlparse.urlsplit(path)
        try:
            reply = recursive_get(self, resource, smap_root)
        except SmapHttpException, err:
            self.send_response(err.code)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            try:
                json.dump(reply, self.wfile)
            except socket.error:
                pass
            except IOError:
                pass
            except ValueError:
                pass

    def do_DELETE(self):
        resource = urlparse.urlsplit(self.path)
        try:
            reply = recursive_method(self, 'http_delete', resource, smap_root)
            self.send_response(200)
            self.end_headers()
        except SmapHttpException, err:
            self.send_response(err.code)
            self.end_headers()

    def do_POST(self):
        self.path = re.sub('/+', '/', self.path)
        self.data = None
        # try to retrieve the request data
        if self.headers.has_key('content-length'):
            try: 
                data = self.rfile.read(int(self.headers['content-length']))
                self.data = json.loads(data)
            except ValueError, e:
                logging.error("error loading JSON object from request!")
                self.send_response(400)
                self.end_headers()
                return
        else:
            self.send_response(400) # no postdata
            self.end_headers()
            return
        
        resource = urlparse.urlsplit(self.path)        
        try:
            object_ = recursive_method(self, 'http_post', resource, smap_root, self.data)
        except SmapHttpException, err:
            self.send_response(err.code)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            json.dump(object_, self.wfile)

    def log_message(self, fmt, *args):
        logging.getLogger('HTTPD').info(self.address_string() + ' - ' + (fmt % args))

    def log_error(self, fmt, *args):
        logging.getLogger('HTTPD').warn(self.address_string() + ' - ' + (fmt % args))


class SslSmapHandler(SmapHandler):
    def setup(self, *args, **kwargs):
        """Override setup so we can initialze a TLS session"""
        baresock = self.request
        sslsock = ssl.wrap_socket(baresock,
                                  server_side=True,
                                  certfile='server_cert.pem',
                                  keyfile='server_key.pem',
                                  ssl_version=ssl.PROTOCOL_TLSv1,
                                  cert_reqs=ssl.CERT_OPTIONAL,
                                  ca_certs='../../ca/cacert.pem')

        # SDH : related to cpython issue #5238, it seems like closing
        # the ssl socket isn't sufficient to disconnect clients; you
        # actually need to call close on the original socket.  This is
        # despite the fact that the ssl wrapper does look like it's
        # doing that.  I'm putting this in as a workaround, but I
        # think this probably introduces some nasty dependencies on
        # python version.
        def new_close():
            ssl.SSLSocket.close(sslsock)
            if sslsock._makefile_refs < 1:
                # sdh : so strange that this is what we need to do.  I
                # am very afraid...
                sslsock.unwrap()
        sslsock.close = new_close        

        self.request = sslsock

        # look up the principal for the server
        # they can trust this since the cert, if present, has been checked
        self.principal = None
        cert = sslsock.getpeercert()
        if cert != None:
            for x in cert['subject']:
                if x[0][0] == 'commonName':
                    self.principal = x[0][1]
                    break

        # call the super handler to finish setting up
        SmapHandler.setup(self)
    

def start_server(root, background=False, port=8080, handler=SmapHandler):
    """Start a sMAP http server

    @root an object representing the web hierarchy to server.  It may
    either be a SmapInstance object, or an arbitrarily-deep set of dicts,
    with all leaf values being SmapInstances.  The server will present
    this hierarchy to the work using HTTP.
    @background if true, fork a thread for the server.  Otherwise, this
    function never returns
    @port local port to run on
    """
    global smap_root, smap_lock
    smap_server_init()
    
    smap_root = root
    server = ThreadedHTTPServer(('', port), handler)

    # this will recursively start any smap instances in the tree
    start_instances(root)

    if background:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        server_thread.start()
        logging.info("Started sMAP Http server thread")
        return server_thread
    else:
        logging.info("Started sMAP Http server inline")
        server.serve_forever()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


if __name__ == '__main__':
    smap_server_init({})
    server = ThreadedHTTPServer(('', 8080), SmapHandler)
    server.serve_forever()

