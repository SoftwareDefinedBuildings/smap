"""Functions and classes for creating an HTTP server providing SMAP
resources and creating response.

To create the simplest SMAP service, first create a SmapInstance
object.  Then start a server using this module.  See the SmapInstance
documentation for more information on adding data.

    data = {
        '0' : {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',multiplier=None,
                                                              divisor=None,type='electric',
                                                              ctype='sensor'),
                                         SmapPoint.Parameter(interval=1, time='second')) } }

    inst = SmapInstance.SmapInstance(data)

    SmapHttp.start_server(inst, port=8080)

    By default, this will block and run in the forground.  If you want
    it to spawn a daemon thread and not do this, you can use the
    background keyword argument:
    
    SmapHttp.start_server.SmapInstance(data, background=True, port=8080)

"""

import json
import urlparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import threading
import thread
import re

import logging
import smaplog
import SmapInstance
import Reporting

class SmapHttpException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "SmapHttpException code: " + str(self.code)

def _recursive_get(path, query, root):
    if isinstance(root, dict):
        if len(path) == 0:
            return root.keys()
        if path[0] == '*':
            rv = {}
            for k,v in root.iteritems():
                rv[k] = _recursive_get(path[1:], query, v)
            return rv
        elif root.has_key(path[0]):
            return _recursive_get(path[1:], query, root[path[0]])
        else:
            raise SmapHttpException(404)
    elif hasattr(root, 'http_get'):
        return root.http_get(path, query=query)
    else:
        # invalid method
        # TODO : the spec says we need to specify an "allow" line of
        # accepted methods
        raise Exception("Invalid HTTP dict!")

def recursive_get(resource, root):
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
            return _recursive_get(path[1:], resource.query, root)
        else:
            # absolute path
            return _recursive_get(path, resource.query, smap_root)
    except Exception, e:
        logging.warn("Exception in recursive get: " + str(e) +
                     "\npath: '" + resource.path + "' query: '" +
                     resource.query + "'")
        if isinstance(e, SmapHttpException):
            raise e
        else:
            raise SmapHttpException(500)
    finally:
        smap_lock.release()

def _recursive_method(method, path, root, *extra):
    if isinstance(root, dict) and len(path) > 0:
        if root.has_key(path[0]):
            return _recursive_method(method, path[1:], root[path[0]], *extra)
    elif hasattr(root, method):
        fn = getattr(root, method)
        return fn(path, *extra)
    else:
        raise SmapHttpException(405)

def recursive_method(method, resource, root, *extra):
    global smap_lock
    path = Reporting.path_segments(resource.path)
    try:
        smap_lock.acquire()
        return _recursive_method(method, path, root, resource.query, *extra)
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
    smap_lock = threading.Lock()
#     smap_root = root
#     smaplog.start_log()

def start_instances(place):
    if isinstance(place, SmapInstance.SmapInstance):
        if not place.is_alive():
            place.start()
    elif isinstance(place, dict):
        for subplace in place.itervalues():
            start_instances(subplace)

def start_server(root, background=False, port=8080):
    global smap_root, smap_lock
    try:
        smap_lock
    except NameError:
        smap_lock = threading.Lock()
        
    smap_root = root
    server = ThreadedHTTPServer(('', port), SmapHandler)

    # this will recursively start any smap instances in the tree
    start_instances(root)

    if background:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        server_thread.start()
        logging.info("Started sMAP Http server thread")
    else:
        logging.info("Started sMAP Http server inline")
        server.serve_forever()


class SmapHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global smap_root
        path = re.sub('/+', '/', self.path)
        resource = urlparse.urlsplit(path)
        try:
            reply = recursive_get(resource, smap_root)
        except SmapHttpException, err:
            self.send_response(err.code)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            json.dump(reply, self.wfile)

    def do_DELETE(self):
        resource = urlparse.urlsplit(self.path)
        try:
            reply = recursive_method('http_delete', resource, smap_root)
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
            object_ = recursive_method('http_post', resource, smap_root, self.data)
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


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

if __name__ == '__main__':
    smap_server_init({})
    server = ThreadedHTTPServer(('', 8080), SmapHandler)
    server.serve_forever()

