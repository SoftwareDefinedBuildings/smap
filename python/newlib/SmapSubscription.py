
import sys
import time
import json
import threading
import httplib
import BaseHTTPServer
import urlparse
import logging
import copy
import traceback
import socket
import atexit

subscriptions = {}
lock = threading.Lock()
LEASE_TIME = 15*60

# SDH : this would be nice if the python multithread signal handling wasn't so broken
def unsubscribe():
    global subscriptions
    for (handler, url, key, create_object) in subscriptions.itervalues():
        log = logging.getLogger("subscription")
        conn = httplib.HTTPConnection(url.netloc, timeout=5)
        log.info("unsubscribing " + url.path + "/reporting/reports/" + key)
        conn.request('DELETE',
                     url.path + '/reporting/reports/' + key,
                     None, {})
        response = conn.getresponse()
        conn.close()
atexit.register(unsubscribe)

def send_subscribe(url, create_object, resource='/reporting/create'):
    log = logging.getLogger('subscription')

    headers = {"Content-type" : "application/json"}
    conn = httplib.HTTPConnection(url.netloc)
    conn.request("POST", 
                 url.path + resource,
                 json.dumps(create_object),
                 headers)
    response = conn.getresponse()
    log.debug("Subscription response: " + str(response.status))

    if response.status == httplib.NOT_FOUND:
        log.error('Error resubscribing: the report instance has been deleted:\n' +
                      str(url))
        conn.close()
        return None
    elif response.status != httplib.OK:
        log.error('When resubscribing, non 200 OK: ' + 
                      str(response) + '\n' + str(url))
        conn.close()
        return None

    reply = json.loads(response.read())
    conn.close()
    return reply

class SmapSubscriptionHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_POST(self):
        global subscriptions, lock
        rv = 200
        data = None
        log = logging.getLogger('subscription')
        
        if self.headers.has_key('content-length'):
            try: 
                data = self.rfile.read(int(self.headers['content-length']))
                data = json.loads(data)
            except ValueError, e:
                log.error("error loading JSON object from request!")
                self.send_response(400)
                self.end_headers()
                return
                
        url = urlparse.urlparse(self.path)
        query = urlparse.parse_qs(url.query)
        if query.has_key('key') and len(query['key']) == 1:
            
            key = int(query['key'][0])

            lock.acquire()
            if subscriptions.has_key(key):
                handler,url,token,object = subscriptions[key]
                try:
                    handler(key, data)
                    rv = 200
                except Exception, e:
                    log.warn("Exception in handler:\n" + str(e))
            else:
                rv = 400
            lock.release()

        self.send_response(rv) 
        self.end_headers()

    def log_message(self, fmt, *args):
        logging.getLogger('subscription').debug(self.address_string() + ' - ' + (fmt % args))

    def log_error(self, fmt, *args):
        logging.getLogger('subscription').warn(self.address_string() + ' - ' + (fmt % args))


class SmapSubscriptionManager(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        global subscriptions, lock
        log = logging.getLogger('subscription')
        while True:
            now = int(time.time())
            lock.acquire()
            my_subs = copy.copy(subscriptions)
            lock.release()
            for k,(handler,url,token,r) in my_subs.iteritems():
                if r['ExpireTime'] < now + 60 :
                    try:
                        new_r = copy.copy(r)
                        new_r['ExpireTime'] = now + LEASE_TIME
                        log.debug('Resubscribing: "' + str(url) + '" "' + token + '"')
                        result = send_subscribe(url, new_r, resource='/reporting/reports/' + 
                                                token)
                        if result != None:
                            r['ExpireTime'] = now + LEASE_TIME
                        else:
                            log.info("Report disappeared -- retrying!")
                            result = send_subscribe(url, new_r)
                            log.info("new subscription: " + str(result))
                            if result:
                                with lock:
                                    subscriptions[k] = (handler, url, result[0], r)

                        log.debug("Result " + str(result))
                    except Exception, e:
                        log.error("Error resubscribing: " + str(e))

            time.sleep(1)


class SmapSubscription(threading.Thread):
    def __init__(self):
        self.httpd_port = None
        self.subscription_key = 0
        self.manager = SmapSubscriptionManager()
        self.log = logging.getLogger('subscription')
        threading.Thread.__init__(self)
        self.setDaemon(True)

        server_address = ('', 0)
        self.httpd = BaseHTTPServer.HTTPServer(server_address, SmapSubscriptionHandler)
        self.host, self.httpd_port = self.httpd.socket.getsockname()[:2]

    def subscribe(self, smap_root, resource, handler, rate=0, localhost=None):
        global subscriptions, lock, LEASE_TIME
        self.subscription_key += 1
        url = urlparse.urlparse(smap_root)
        if not url or url.scheme != 'http':
            return None

        if not localhost:
            try:
                localhost=socket.gethostbyname(socket.getfqdn())
            except socket.gaierror:
                self.log.fatal("Cannot determine local address; aborting")
                sys.exit(1)
            self.log.warn("No local address provided; guessing " + str(localhost))

        create_object = {
            "$schema" : {"$ref" : "http://webs.cs.berkeley.edu/schema/meter/reporting/create"},
            "Period"  : rate,
            "ReportResource" : resource,
            "ReportDeliveryLocation" : 'http://%s:%i/?key=%i' % (localhost, 
                                                                 self.httpd_port, self.subscription_key),
            "ExpireTime" : int(time.time() + LEASE_TIME),
            }

        self.log.info("Subscribing to " + create_object['ReportResource'])
        reply = send_subscribe(url, create_object)
        if reply:
            lock.acquire()
            try:
                subscriptions[self.subscription_key] = (handler, url, reply[0], create_object)
            except:
                pass
            finally:
                lock.release()
            return self.subscription_key
        return None

    def start(self):
        self.manager.start()
        threading.Thread.start(self)

    def run(self):
        self.log.info('Subscription manager started on (%s, %i)' % (self.host, self.httpd_port))
        self.httpd.serve_forever()
