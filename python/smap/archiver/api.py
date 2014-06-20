"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import traceback
import time
import json
import operator
import urllib
import csv
import datetime
import logging

from twisted.internet import reactor, threads, defer
from twisted.web import resource, server
from twisted.web.resource import NoResource
from twisted.python import log

import smap.util as util
import smap.sjson as json
from smap.server import setResponseCode
from smap.core import SmapException
from smap.contrib import dtutil
from data import escape_string, data_load_result, makeErrback
import queryparse as qp
from querygen import build_authcheck
import settings
import stream
from consumers import make_time_formatter

class ApiResource(resource.Resource):
    def __init__(self, db):
        self.db = db
        resource.Resource.__init__(self)

class SubscriptionResource(ApiResource):
    """Show the client a list of sMAP sources, or a small description
    of the streams associated with one subscription.
    """
    def getChild(self, name, resource):
        return self

    def _done_subs(self, request, result):
        try:
            result = [{'id' : x[0],
                       'SmapUrl' : x[1],
                       'ReportResource' : x[2]} for x in result]
            d = util.AsyncJSON(result).startProducing(request)
            d.addBoth(lambda _: request.finish())
        except:
            traceback.print_exc()

    def _done_streams(self, request, result):
        result = [{'Path' : x[0],
                   'uuid' : x[1]} for x in result]
        result.sort(key=operator.itemgetter('Path'))
        d = util.AsyncJSON(result).startProducing(request)
        d.addBoth(lambda _: request.finish())

    def render_GET(self, request):
        if len(request.prepath) == 2 or \
                (len(request.prepath) == 3 and request.prepath[-1] == ''):
            d = self.db.runQuery("""
SELECT id, url, resource
FROM subscription sub WHERE """ + build_authcheck(request))
            d.addCallback(lambda x: self._done_subs(request, x))
            d.addErrback(makeErrback(request))
        else:
            when = int(time.time()) * 1000

            d = self.db.runQuery("""
SELECT m.tagval, s.uuid
FROM subscription sub, stream s, metadata2 m
WHERE """ + build_authcheck(request) + """ AND 
    tagname = 'Path' AND
    m.stream_id = s.id AND
    s.subscription_id = sub.id AND
    sub.id = %s 
""", (int(request.prepath[-1]), ))
            d.addCallback(lambda x: self._done_streams(request, x))
            d.addErrback(makeErrback(request))
        return server.NOT_DONE_YET

def build_inner_query(request, tags):
    """Build an "inner query" -- a query which yields a list of stream
    ids (indexes in the stream table).  These match the identifiers
    used in the reading db, or can be used as part of a join.  The
    query performs auth checks and will check for the tags specified.
    """
    # the inner query builds a list of streams matching all the
    # clauses which we can then select from
    clauses = []
    uuid_clause = "true"
    for (k, v) in tags:
        if k == 'uuid': 
            if v != None:
                uuid_clause = "s.uuid = %s" % escape_string(v)
            continue
        if v != None:
            clauses.append("hstore(%s, %s)" % (escape_string(k),
                                               escape_string(v)))
        else: break

    if len(clauses) == 0: clauses = ["hstore(array[]::varchar[])"]
    inner_query = """
 (SELECT s.id FROM stream s, subscription sub
  WHERE s.subscription_id = sub.id AND (%s) AND (%s) AND s.metadata @> (%s))
""" % (build_authcheck(request), uuid_clause, ' || '.join(clauses))

    return inner_query, clauses

def log_time(result, start):
    logging.getLogger('stats').info("api query took %0.6fs" % (time.time() - start))
    return result

def build_query(db, request, tags):
    """Will wrap a query which an appropriate selector to yield
    distinct tagnames, tagvals, or uuids depending on what is needed.
    """
    inner_query, clauses = build_inner_query(request, tags)
    if len(tags) and tags[-1][0] == 'uuid':
        # if we select uuid as the trailing tag we have to be special
        query = """
SELECT DISTINCT s.uuid 
FROM stream AS s
WHERE s.id IN """ + inner_query
    elif len(tags) and (tags[-1][1] == None or tags[-1][1] == ''):
        # odd-numbered clasues, so we print matching values of tags
        t = escape_string(tags[-1][0])
        query = """
SELECT DISTINCT metadata -> %s AS svals FROM stream
WHERE id IN %s AND metadata ? %s
ORDER BY svals ASC""" % (t, inner_query, t)
    else:
        # otherwise we print all tags matching the restriction
        query = """
SELECT DISTINCT skeys
FROM (
  SELECT skeys(metadata) FROM stream
  WHERE id IN %s
) AS skeys ORDER BY skeys ASC""" % inner_query

    log.msg(query)
    d = db.runQuery(query)
    d.addCallback(log_time, time.time())
    return d

def build_tag_query(db, request, tags):
    """Wraps an inner query to select all tags for streams which match
    the tags query.
    """
    inner_query, clauses = build_inner_query(request, tags)
    query = """
SELECT s.metadata || hstore('uuid', s.uuid)
FROM stream s
WHERE s.id IN """ + inner_query + """
ORDER BY s.id ASC"""
    log.msg(query)
    d = db.runQuery(query)
    d.addCallback(log_time, time.time())
    return d


class Api(resource.Resource):
    """Provide api calls against the databases for data and tag lookups.
    """
    def __init__(self, db):
        self.db = db
        resource.Resource.__init__(self)

    def generic_extract_result(self, request, result):
        """Extract postgres results which are just wrapped with an extra
        list"""
        return request, map(operator.itemgetter(0), result)

    def tag_extract_result(self, request, result):
        """For a tag query, we want to return a nested dict so we pipe the
        result through this filter instead.
        """
        return request, map(lambda x: util.build_recursive(x[0], suppress=[]), 
                            result)

    def write_one_stream(self, request, stream, stags, mime_header=False):
        """For a CSV downlod, add some hweaders and write the data to the stream
        """
        writer = csv.writer(request)
        if 'tags' in request.args and not 'none' in request.args['tags']:
            request.write("# uuid: %s\n" % stream['uuid'])
            request.write("# DownloadTime: " + time.ctime() + "\n")
            request.write("# ")
            request.write('\n# '.join((': '.join(x) for x in sorted(stags.iteritems()))))
            request.write('\n')

            time_formatter = make_time_formatter(request, stags)
            def row_action(row):
                row[0] = time_formatter(row[0])
                writer.writerow(row)
            map(row_action, stream['Readings'])
        else:
            map(writer.writerow, stream['Readings'])

    def send_csv_reply(self, request, result, tags):
        """CSV replies are easy"""
        request.setHeader('Content-disposition', 'attachment; filename=%s.csv' % 
                          result[0]['uuid'])
        if tags[0][0]:
            tags = tags[0][1][0][0]
        else:
            tags = None
        self.write_one_stream(request, 
                              result[0], 
                              tags)        
        request.finish()

    def send_data_reply(self, (request, result)):
        """After reading back some data, format it and send it to the client
        """
        if not 'format' in request.args or 'json' in request.args['format']:
            return self.send_reply((request, result))
        elif 'format' in request.args and 'csv' in request.args['format']:
            if len(result) > 1:
                request.setResponseCode(400)
                request.write("CSV only supported for one data stream")
                request.finish()
                return
            # return cvs
            request.setHeader('Content-type', 'text/csv')
            if ('tags' in request.args or
                ('timefmt' in request.args and request.args['timefmt'][0] in ['excel', 'iso8060'])):
                dl = []
                for str in result:
                    dl.append(build_tag_query(self.db, request, [('uuid', str['uuid'])]))
                d = defer.DeferredList(dl)
                d.addCallback(lambda x: self.send_csv_reply(request, result, x))
                return d
            else:
                return self.send_csv_reply(request, result, [(False, [])] * len(result))
        else:
            request.setResponseCode(400)
            request.finish()

    def send_reply(self, (request, result)):
        """Send a generic json reply.
        """
        if not 'callback' in request.args:
            return self.send_json(request, result)
        else:
            return self.send_jsonp(request.args['callback'][0], request, result)

    def send_json(self, request, result):
        try:
            request.setHeader('Content-type', 'application/json')
            request.write(json.dumps(result))
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            log.err()
            raise

    def send_jsonp(self, callback, request, result):
        try:
            request.setHeader('Content-type', 'text/javascript')
            request.write(callback + '(')
            request.write(json.dumps(result))
            request.write(');')
            request.finish()
            return server.NOT_DONE_YET
        except Exception, e:
            log.err()
            raise

    def send_error(self, request, error):
        log.err(error)
        setResponseCode(request, error, 400)
        try:
            request.write(str(error.value))
        except:
            request.write(str(error))
        request.unregisterProducer()
        request.finish()
        return str(error)
    

    def getChild(self, name, request):
        # except for streams, all api resources specify a set of
        # streams using a query path.  therefore they all operate on
        # sets of streams.
        if name == 'streams':
            return SubscriptionResource(self.db)
        else:
            return self

    def render_POST(self, request, query=None):
        """The POST method is only used for sql-like queries.

        The logic for parsing the query, building the true SQL
        statement, and parsing out the results are in the queryparse
        and querygen modules.
        """
        # make a parser and parse the request
        parser = qp.QueryParser(request)
        if not query: query = request.content.read() 
        try: 
            # run the query locally
            d = parser.runquery(self.db, query)
        except Exception, e:
            log.err("Failing query: " + str(query))
            log.err()
            setResponseCode(request, e, 400)
            return str(e)
        else:

            if not query.strip().startswith('apply'):
                # and send the reply
                request.setHeader('Content-type', 'application/json')

                # apply streams the output out itself
                d.addCallback(lambda reply: (request, reply))
                d.addCallback(self.send_reply)
            d.addErrback(lambda x: self.send_error(request, x))
            return server.NOT_DONE_YET

    def render_GET(self, request):
        """The GET method exposes a RESTful API to ARD functions.

        This lets clients look at tags and get data.
        """
        if len(request.prepath) == 1:
            return self.send_reply((request, {'Contents': ['streams', 'query', 'data', 
                                                           'next', 'prev', 'tags',
                                                           'operators']}))
        # start by looking up the set of streams we are going to operate on
        path = map(lambda x: x.replace('__', '/'), request.prepath[2:])
        path = map(urllib.unquote, path)
        method = request.prepath[1]

        # dispatch based on the method name
        if method != 'query':
            if len(path) % 2 != 0:
                request.setResponseCode(400)
                request.finish()
                return server.NOT_DONE_YET
            path.append('uuid')            
        if method == 'query':
            if 'q' in request.args:
                return self.render_POST(request, request.args['q'][0])
            else:
                # this allows a user to enumerate tags
                d = build_query(self.db,
                                request,
                                zip(path[::2], 
                                    path[1::2] + [None]))
                d.addCallback(lambda r: self.generic_extract_result(request, r))
                d.addCallback(self.send_reply)
                d.addErrback(lambda x: self.send_error(request, x))
        elif method == 'tags':
            # retrieve tags
            d = build_tag_query(self.db,
                                request, 
                                zip(path[::2], 
                                    path[1::2] + [None]))
            d.addCallback(lambda r: self.tag_extract_result(request, r))
            d.addCallback(self.send_reply)
            d.addErrback(lambda x: self.send_error(request, x))

        elif method in ['data', 'next', 'prev']:
            # retrieve data
            d = self.db.runQuery("""SELECT uuid, id FROM stream WHERE
id IN """ + build_inner_query(request,
                              zip(path[::2], 
                                  path[1::2] + [None]))[0])
            d.addCallback(log_time, time.time())
            d.addCallback(lambda r: data_load_result(request, method, r))
            d.addCallback(lambda d: (request, d))
            d.addCallback(self.send_data_reply)
            d.addErrback(lambda x: self.send_error(request, x))
        elif method == 'operators':
            self.send_reply((request, stream.installed_ops.keys()))
        else:
            request.setResponseCode(404)
            request.finish()

        return server.NOT_DONE_YET

