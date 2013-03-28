#!/usr/bin/python
# -*- python -*-
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

import sys
import csv
import uuid
import time
import unicodedata
from optparse import OptionParser

from twisted.internet import reactor
from twisted.python import log
from smap.core import SmapInstance
from smap.contrib import dtutil

def path(col):
    v = unicode(col, errors='ignore').encode('ascii', errors='xmlcharrefreplace')
    # v = col.encode('utf-8079', errors='replace').encode('ascii', errors='xmlcharrefreplace')
    # print col.encode('utf-8', errors='xmlcharrefreplace')
    # print col.encode('utf-8', errors='xmlcharrefreplace')
    return v

def make_field_list(fields, spec):
     takes = []
     for c in spec.split(','):
         try:
             c = int(c)
             takes.append(c)
         except ValueError:
             for (i, h) in enumerate(fields):
                 if c == h:
                     takes.append(i)
                     break
     return set(takes)

def make_path_names(fields):
    names = {}
    for (i, n) in enumerate(fields):
        if n in fields[:i] + fields[i+1:]:
            idx = len(filter(lambda x: x == n, fields[:i]))
            names[i] = path(n + '_%i' % idx)
        else:
            names[i] = path(n)
    return names

def field_idx(fields, name):
    try:
        i = int(name)
        return i
    except ValueError:
        return fields.index(name)

def unquote(s):
    if ((s[0] == '"' and s[-1] == '"') or 
        (s[0] == "'" and s[-1] == "'")):
        return s[1:-1]
    else:
        return s

if __name__ == '__main__':
    usage = 'usage: %prog [options] <csvfile>'
    parser = OptionParser(usage=usage)

    parser.add_option('-u', '--uuid', dest='uuid', 
                      default='9ffb78a6-4c6a-11e2-b19e-d78597b0c967',
                      help='root uuid')
    parser.add_option('-i', '--ignore-channels', dest='ignore',
                      default='', help='comma-separated list of column names '
                      'or indexes to ignore')
    parser.add_option('-c', '--take-channels', dest='takes',
                      default='', help='comma-separated list of column names '
                      'or indexes to load')
    parser.add_option('-t', '--time-channel', dest='time',
                      default='', help='name or index of the column with '
                      'timestamps')
    parser.add_option('-f', '--time-format', dest='time_format',
                      default='%s', help='format string used to parse the '
                      'timestamps')
    parser.add_option('-z', '--time-zone', dest='time_zone',
                      default='America/Los_Angeles', help='time zone name')
    parser.add_option('-d', '--report-dest', dest='report_dest',
                      default=None, help='reporting destination')
    parser.add_option('-v', '--verbose', dest='verbose',
                      default=False, help='verbose', action='store_true')
    parser.add_option('-k', '--skip-lines', dest='skip_lines',
                      default=0, type='int', help='number of lines to skip')
    parser.add_option('-l', '--limit-lines', dest='limit', type='int',
                      default=None, help='only process this many lines from the file')
    parser.add_option('-s', '--source-name', dest='source_name',
                      default='CSV Input', help='Metadata/SourceName tag value')

    opts, args = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit(1)
    
    try:
        uid = uuid.UUID(opts.uuid)
    except ValueError:
        print >>sys.stderr, "Error: invalid UUID:", opts.uuid
        sys.exit(1)

    try:
        fp = open(args[0], 'rU')
        for i in xrange(0, opts.skip_lines): fp.readline()
    except IOError, e:
        print >>sys.stderr, "Error:", e
        sys.exit(1)

    data = csv.reader(fp)
    fieldnames = data.next()
    columns = set(xrange(0, len(fieldnames)))
    paths = make_path_names(fieldnames)

    # choose the columns 
    if opts.takes:
        columns.intersection_update(make_field_list(fieldnames, opts.takes))
    if opts.ignore:
        columns.difference_update(make_field_list(fieldnames, opts.ignore))

    # pick the time field
    if opts.time:
        t = field_idx(fieldnames, opts.time)
    else:
        t = 0
    columns.difference_update(set([t]))

    # okay, so we're set up with a time column and a list of other
    # columns to take.
    log.startLogging(sys.stderr)
    inst = SmapInstance(uid)
    inst.set_metadata('/', {'Metadata/SourceName': opts.source_name})
    if opts.report_dest:
        inst.reports.del_report(uuid.uuid5(uid, opts.report_dest))
        inst.reports.add_report({
                'ReportDeliveryLocation' : [opts.report_dest],
                'uuid': uuid.uuid5(uid, opts.report_dest),
                'ReportResource' : '/+',
                'Format' : 'json',
                })
    else:
        print >>sys.stderr, "Warning: no reporting destination"

    for c in columns:
        if opts.verbose: print "timeseries %s tz: %s" % (paths[c], opts.time_zone)
        inst.add_timeseries(paths[c], '', 
                            timezone=opts.time_zone,
                            data_type='double')

    processed = 0
    for r in data:
        if opts.limit != None and processed >= opts.limit:
            break
        else:
            processed += 1

        if opts.time_format == '%s':
            ts = int(r[t])
        else:
            ts = dtutil.dt2ts(dtutil.strptime_tz(r[t], opts.time_format))

        if opts.verbose: print ts
        for c in columns:
            if not r[c]: continue
            if opts.verbose: print "\t %s '%s' added" % (paths[c], r[c])
            inst._add(paths[c], ts, float(r[c]))

    print "processed %i lines" % processed
    if opts.report_dest:
        d = inst._flush()
        d.addCallbacks(lambda x: reactor.stop())
        reactor.run()
