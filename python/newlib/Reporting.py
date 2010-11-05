
import os
import sys
import pickle
import logging
import threading
import time
import random
import string
import urlparse
import json
import httplib

import SmapHttp
import ThreadPool

def path_segments(path):
    segs = filter(lambda x: x != '', path.split('/'.strip()))
    segs.reverse()
    try:
        segs = segs[:segs.index('~')+1]
        segs.reverse()
        return segs
    except:
        segs.reverse()
        return segs

class Reporting(threading.Thread):
    """Manage delivering reports which have been installed.
    """
    RETRY_TIMEOUT = 3600 * 24

    def __init__(self, resource_root, report_file=None):
        threading.Thread.__init__(self)

        if not report_file:
            report_file = '/var/smap/' + '-'.join(sys.argv) + '-reports'
        try:
            os.makedirs(os.path.dirname(report_file))
        except:
            pass
        print report_file

        self.logger = logging.getLogger("ReportingCollection")
        self.report_file = report_file
        self.current_reports = self._load_reports()
        self.cv = threading.Condition()
        self.pool = ThreadPool.ThreadPool(5)
        self.resource_root = resource_root
        self.setDaemon(True)

        self.logger.info("Using '%s' to cache report instances" % report_file)

    def _save_reports(self):
        """
        Save the state of all current reporting instances to the
        backing store.

        must be called with current_reports locked
        """
        with open(self.report_file, "w") as fp:
            pickle.dump(self.current_reports, fp)
            self.logger.debug("Saved report object to '" + self.report_file + "'")

    def _load_reports(self):
        """
        Read in saved reporting instances from backing store; returns
        the laoded values.
        """
        try:
            fp = open(self.report_file, "r")
            rv = pickle.load(fp)
            fp.close()
            self.logger.info("Loaded report object from '" + self.report_file + "'")
        except Exception, e:
            rv = {}
        return rv

    def _next_deadline(self):
        """
        Determine the next pending deadline, for reports which are
        configured with periodic (rather then event-driven) reporting.

        must be called with current_reports locked
        """
        deadline = None
        now = time.time()
        for report in self.current_reports.itervalues():
            if report['Period'] == 0:
                continue
            if report.get('Pending'):
                continue

            # it's either the next report or the expire time
            next = report['LastReport'] + report['Period']
            if report.has_key('ExpireTime'):
                next = min(next, report['ExpireTime'])

            if next < now:
                return 0
            elif next > now and (next - now < deadline or not deadline):
                deadline = next - now
        return deadline

    def _alloc_reportname(self):
        """
        Generate a new, unique key to use as the resource name for a
        report.

        must be called with current_reports locked
        """
        key = "".join(random.sample(string.letters+string.digits, 8))
        while self.current_reports.has_key(key):
            key = "".join(random.sample(string.letters+string.digits, 8))
        return key

    def _deliver(self, (key, result)):
        """
        Attempt delivery of a sMAP report to an endpoint; generally
        posted to a thread pool for deferred execution.

        @key the reporting instance name
        @result the object to be HTTP POSTed to the endpoint.
        """
        remove = False
        try:
            self.cv.acquire()
            has_lock = True

            # might have gotten deleted before we run
            if not self.current_reports.has_key(key): return
            report = self.current_reports[key]

            headers = {"Content-type" : "application/json"}
            data = json.dumps(result)
            url = report['ReportDeliveryLocation'].path + "?" + \
                report['ReportDeliveryLocation'].query

            # this stores the last time we tried to deliver something
            report['LastReport'] = time.time()

            conn = httplib.HTTPConnection(report['ReportDeliveryLocation'].netloc, 
                                          timeout=10)
            self.cv.release()
            has_lock = False

            # this is the part that might timeout; attempt it with the
            # reporting structure unlocked.
            conn.request("POST", 
                         url,
                         data,
                         headers)
            response = conn.getresponse()
            conn.close()
             
            self.cv.acquire()
            has_lock = True

            # need to check this again.
            if not self.current_reports.has_key(key): return

            self.logger.info("delivered report to '" + 
                             report['ReportDeliveryLocation'].netloc + 
                             "', response: " + 
                             str(response.status) + ' ' +
                             str(response.reason))
            self.logger.debug("request string: " + url)

            if response.status == httplib.OK or \
                    response.status == httplib.ACCEPTED or \
                    response.status == httplib.CREATED:
                # this means everything worked
                report['LastSuccess'] = time.time()

        except IOError, err:
            # del self.current_reports[key]
            self.logger.info("Delivering report: Connection error: " + str(err) + 
                             "\nreport instance:\n" + str(report))
        except Exception, err:
            # del self.current_reports[key]
            self.logger.warn("Other exception while delivering exception:\n" + 
                             str(err) +
                             "\nreport instance:\n" + str(report))
        finally:
            if not has_lock:
                self.cv.acquire()
            if self.current_reports.has_key(key): 
                self.current_reports[key]['Pending'] = False
            self.cv.notify()
            self.cv.release()

    def push(self, dirty_path="~/"):
        """can be called to "push" out new reports to any clients who
            have asked to receive a stream of reports rather then a fixed
            period

           if dirty_path is provided, it will only push out reports
            where the request path starts with the request string specified.
        """
        dirty_path = path_segments(dirty_path)

        self.cv.acquire()
        for (key, report) in self.current_reports.iteritems():
            # only guys with period zero get pushed data; the rest
            # will happen from the report thread
            if report['Period'] > 0:
                continue
            
            # build the report object we need to pass out
            try:
                data = SmapHttp.recursive_get(report['ReportResource'],
                                              self.resource_root)
            except SmapHttp.SmapHttpException, e:
                logging.warn("Invalid report resource in push: '%s, %s" %
                             (str(report['ReportResource']), str(e)) )
                continue

            # prune the non-dirty parts of the report here
            req_path = path_segments(report['ReportResource'].path)

            def compare_dirty(dirty, request, rv_data):
                if len(dirty) == 0 or len(request) == 0:
                    return rv_data
                elif dirty[0] == request[0]:
                    # if we match so far, need to explore the children.
                    # data won't contain any of these path elements
                    return compare_dirty(dirty[1:], request[1:], rv_data)
                elif request[0] == '*' and dirty[0] == '*':
                    return compare_dirty(dirty[1:], request[1:], rv_data)
                elif request[0] == '*':
                    # we need to filter out everything but the dirty
                    # element, and keep looking
                    rv = {}
                    if rv_data.has_key(dirty[0]):
                        rv[dirty[0]] = rv_data[dirty[0]]
                        return compare_dirty(dirty[1:], request[1:], rv)
                    else:
                        return None
                elif dirty[0] == '*':
                    return compare_dirty(dirty[1:], request[1:], rv_data)                    
                else:
                    return None

            data = compare_dirty(dirty_path, req_path, data)

            # if anything matched, push it onto the queue for delivery
            if data:
                self.pool.queueTask(self._deliver, args=(key, data))

        self._save_reports()
        self.cv.release()

    def run(self):
        time.sleep(30)
        self.cv.acquire()
        self.logger.info("report delivery thread running")
        while (True):
            del_keys = []
            d = self._next_deadline()
            self.logger.debug("Next deadline: " + str(d))
            # this might get interrupted by a signal, but that's okay;
            # we'll just check and continue sleeping.
            self.cv.wait(d)

            for (key, report) in self.current_reports.iteritems():
                if report.has_key('ExpireTime'):
                    if report['ExpireTime'] < time.time():
                        self.logger.info("expiring report\n" + str(report))
                        del_keys.append(key)
                        continue

                if (report['LastReport'] + report['Period'] < time.time()) and \
                        report['Period'] > 0:
                    # reports are the same as doing a GET on the
                    # specified resource
                    try:
                        result = SmapHttp.recursive_get(report['ReportResource'],
                                                        self.resource_root)
                    except SmapHttp.SmapHttpException:
                        self.logger.warn("Invalid resource in periodic report: '%s'" %
                                         str(report['ReportResource']))
                        continue

                    # immediately remove requests where the resource is invalid
                    if (result == None and \
                            time.time() - report['LastSuccess'] > \
                            self.RETRY_TIMEOUT) or \
                            report['ReportDeliveryLocation'].scheme != "http":
                        self.logger.warn("removing failed report:", key) 
                        del_keys.append(key)
                        continue

                    if result == None:
                        continue

                    report['Pending'] = True
                    self.pool.queueTask(self._deliver, args=(key, result))

                if time.time() - report['LastSuccess'] > self.RETRY_TIMEOUT:
                    self.logger.warn("removing report to '" + 
                                     report['ReportDeliveryLocation'].netloc +
                                     "' due to delivery failure (" + key + ")")
                    del_keys.append(key)

            for k in del_keys:
                del self.current_reports[k]
            self._save_reports()

    def _validate_report(self, req):
        """
        Validate a reporting object abd parse the fields.

        A reporting object MUST contain Period,
        ReportDeliveryLocation, and ReportResource keys
        
        Period -- integer
        ReportDeliveryLocation -- valid URL
        ReportResource -- a local resource, starting with the root of the SMAP instance
        """

        # check the right fields are there
        required_fields = ['Period', 'ReportDeliveryLocation', 'ReportResource']
        optional_fields = ['ExpireTime', 'LastReport', 'LastSuccess']
        for k in req.keys():
            if k not in required_fields + optional_fields:
                del req[k]

        for k in required_fields:
            if not req.has_key(k):
                return None

        try:
            # try to parse the fields
            req['ReportDeliveryLocation'] =  urlparse.urlparse(req['ReportDeliveryLocation'])
            req['ReportResource'] = urlparse.urlparse(req['ReportResource'])
            req['Period'] = int(req['Period'])

        except Exception, e:
            self.logger.error("Validating report exception!: " + str(e))
            return None

        return req

    def create_report(self, reqobj):
        # first create a new empty report
        self.cv.acquire()
        try:
            report_name = self._alloc_reportname()
            self.current_reports[report_name] = {}
        except Exception, e:
            raise e
        finally:
            self.cv.release()

        try:
            # try to update it
            reqobj['LastReport'] = int(time.time())
            reqobj['LastSuccess'] = int(time.time())
            self.update_report(report_name, reqobj)

        except SmapHttp.SmapHttpException, e:
            # but if the request is invalid, delete the new instance
            self.cv.acquire()
            self.logger.warn("Exception in update", e)
            del self.current_reports[report_name]
            self.cv.release()
            raise e

        return report_name

    def update_report(self, name, reqobj):
        reqobj = self._validate_report(reqobj)
        if reqobj == None:
            # bad request
            raise SmapHttp.SmapHttpException(400)
        self.cv.acquire()
        try:
            self._save_reports()
            self.current_reports[name].update(reqobj)
            self.cv.notify()
        finally:
            self.cv.release()
        return name
        
    def delete_report(self, name):
        self.cv.acquire()
        try:
            if self.current_reports.has_key(name):
                del self.current_reports[name]
                self.logger.info("deleting report with key " + name)
                self.cv.notify()
            else:
                raise SmapHttp.SmapHttpException(404)
        except Exception, e:
            raise e
        finally:
            self.cv.release()

    def report_list(self):
        self.cv.acquire()
        try:
            return self.current_reports.keys()
        except:
            return []
        finally:
            self.cv.release()

    def report_get(self, name):
        self.cv.acquire()
        try:
            return self.current_reports[name].copy()
        except:
            return None
        finally:
            self.cv.release()


##
## HTTP Handlers for Reporting
##

class ReportingHttp(dict):
    """
    A class to provide the HTTP layer on top of the actual reporting object
    """
    def __init__(self, report):
        self.report = report
        self.__setitem__('create', ReportingHttpCreate(report))
        self.__setitem__('reports', ReportingHttpCollection(report))

class ReportingHttpCreate:
    def __init__(self, report):
        self.report = report

    def http_post(self, resource, query, postobject):
        return [self.report.create_report(postobject)]

class ReportingHttpCollection:
    def __init__(self, report):
        self.report = report

    def http_get(self, resource, query):
        if len(resource) == 0:
            return self.report.report_list()
        else:
            report = self.report.report_get(resource[0])
            if not report:
                raise SmapHttp.SmapHttpException(404)
            report['ReportDeliveryLocation'] = urlparse.urlunparse(report['ReportDeliveryLocation'])
            report['ReportResource'] = urlparse.urlunparse(report['ReportResource'])
            return report

    def http_post(self, resource, query, postobject):
        if len(resource) != 1:
            # method not available
            raise SmapHttp.SmapHttpException(405)
        else:
            try:
                return self.report.update_report(resource[0], postobject)
            except KeyError:
                raise SmapHttp.SmapHttpException(404)

    def http_delete(self, resource, query):
        if len(resource) == 1:
            self.report.delete_report(resource[0])
        elif len(resource) == 0:
            # method not available
            raise SmapHttp.SmapHttpException(405)
        else:
            raise SmapHttp.SmapHttpException(404)
