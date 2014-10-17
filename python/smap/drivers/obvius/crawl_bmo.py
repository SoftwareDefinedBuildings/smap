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

import sys
import re
import pprint
from BeautifulSoup import BeautifulSoup as bs
from smap.iface.http.httputils import load_html
from optparse import OptionParser
import ConfigParser
import urllib
import urlparse

import ConfigParser
try:
    import ordereddict
except ImportError:
    import collections as ordereddict


try:
    import ordereddict
except ImportError:
    import collections as ordereddict

sys.path.append("../../newlib")
import sensordb
import auth


BMOROOT = 'http://www.buildingmanageronline.com/members/'
STATUSPAGE = 'client_status.php?DB=dbU216ucberkelF682'
AUTH = ('ucbguest', 'ucbguest')

def remove_entities(s):
    return re.sub('&.*;', '', s)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-t', '--types', dest='types', action='store_true', default=False,
                      help='print the types of devices found')
    parser.add_option('-n', '--no-cache', dest='cache', action='store_false', default=True,
                      help='do not use cached pages')
    parser.add_option('-b', '--buildings', dest='buildings', action='store_true', default=False,
                      help='show building list')
    parser.add_option('-p', '--progress', dest='progress', action='store_true', default=False,
                      help='show buildings as we load them')
    parser.add_option('-l', '--load', dest='load', action='store_true', default=False,
                      help='generate conf for loading data from bmo')
    parser.add_option('-d', '--database', dest='db', action='store_true', default=False,
                      help='generate a prototype sensordb for an instrument')
    (opts, args) = parser.parse_args()
    opts.conf = True
    if opts.types or opts.buildings or opts.load or opts.db:
        opts.conf = False

    # find all the AcquiSuite boxes
    devices = {}
    soup = load_html(BMOROOT + STATUSPAGE, auth=AUTH, cache=opts.cache)
    for tr in soup.findAll('tr'):
        tds = tr('td')
        if len(tds) != 6: continue
        
        name = tds[0].a.string
        devices[name] = {
            'ip' : remove_entities(tds[3].string),
            'href' : tds[0].a['href'],
            }

    # look at all the meters hanging off each of them
    for location in devices.iterkeys():
        if opts.progress:
            print >>sys.stderr, "Processing", location
        soup = load_html(BMOROOT + devices[location]['href'], auth=AUTH, cache=opts.cache)
        subdevices = []
        for tr in soup.findAll('tr'):
            tds = tr('td')
            if len(tds) != 5 or tds[3].a != None: continue

            subdevices.append({
                    'address' : remove_entities(tds[0].string),
                    'name' : remove_entities(tds[2].string),
                    'type' : remove_entities(tds[3].string)
                    })
        devices[location]['subdevices'] = subdevices
    
    if opts.types:
        mtypes = {}
        for name, v in devices.iteritems():
            for t in v['subdevices']:
                if not t['type'] in mtypes:
                    mtypes[t['type']] = {'count': 0, 'locs': []}
                mtypes[t['type']]['count'] = mtypes[t['type']]['count'] + 1
                mtypes[t['type']]['locs'].append(name)
        for n, c in mtypes.iteritems():
            print >>sys.stderr, c['count'], n, ' '.join(c['locs'])

    if opts.buildings:
        print >>sys.stderr, '\n'.join(devices.iterkeys())

if opts.conf:
    def make_section(cmps):
        # cmps = map(lambda s: s.replace(' ', '_'), cmps)
        # return '/' + '/'.join(map(lambda s: urllib.quote(s, safe=''), cmps))i
        import random
        return 'path' + str(random.randint(0, 100000000))

    conf = ConfigParser.ConfigParser('', ordereddict.OrderedDict)
    conf.optionxform = str
    conf.add_section('/')
    conf.set('/', 'Metadata/Location/Campus', 'UCB')
    conf.set('/', 'type', 'Collection')
    
    for location, devs in devices.iteritems():
        if not location in auth.AUTH: continue

        parent_sec = make_section((location, ))
        conf.add_section(parent_sec)
        conf.set(parent_sec, 'type', 'Collection')
        conf.set(parent_sec, 'Metadata/Location/Building', location)
        
        sec = None
        for d in devs['subdevices']:
            map = sensordb.get_map(d['type'], location)
            if map != None:
                sec = make_section((location, d['name']))
                conf.add_section(sec)
                conf.set(sec, 'type', 'smap.drivers.obvius.obvius.Driver')
                conf.set(sec, 'Username', auth.AUTH[location][0])
                conf.set(sec, 'Password', auth.AUTH[location][1])
                conf.set(sec, 'Url', 'http://' + devs['ip'] + 
                         '/setup/devicexml.cgi?ADDRESS=%s&TYPE=DATA' % d['address'],)
                conf.set(sec, 'ObviousType', d['type'])
        if sec == None:
            conf.remove_section(parent_sec)

    conf.write(sys.stderr)
elif opts.load:
    conf = {}
    for location, devs in devices.iteritems():
        params = urlparse.parse_qs(urlparse.urlsplit(devs['href']).query)
        if not "AS" in params or not  "DB" in params: continue
        if location in auth.AUTH: continue
        thisconf = {}
        for d in devs['subdevices']:
            if sensordb.get_map(d['type'], location) != None:
                dlurl = BMOROOT + 'mbdev_export.php/' + params['AS'][0] + '_' +  \
                    d['address'] + '.csv' + "?DB=" + params['DB'][0] + '&AS=' + \
                    params['AS'][0] + '&MB=' + d['address'] + '&DOWNLOAD=YES' + \
                    "&COLNAMES=ON&EXPORTTIMEZONE=UTC&DELIMITER=TAB" + \
                    '&DATE_RANGE_STARTTIME=%s&DATE_RANGE_ENDTIME=%s'
                thisconf[d['name']] = (
                    d['type'],
                    dlurl)

        if len(thisconf) > 0:
            conf[location] = thisconf

    # generate config file
    cf = ConfigParser.ConfigParser('', ordereddict.OrderedDict)
    cf.optionxform = str
    import obvius
    cf.add_section('server')
    cf.set('server', 'SuggestThreadPool', '20')
    cf.set('server', 'Port', '9051')

    cf.add_section('/')
    cf.set('/', 'Metadata/Location/Campus', 'UCB')
    cf.set('/', 'Metadata/SourceName', 'buildingmanageronline archive')
    cf.set('/', 'uuid', '91dde108-d02b-11e0-8542-0026bb56ec92')

    for building in conf.iterkeys():
        building_path = '/' + obvius.to_pathname(building)
        cf.add_section(building_path)
        cf.set(building_path, 'type', 'Collection')
        for metername in conf[building].iterkeys():
            metertype, url = conf[building][metername]

            building_name = building
            if "New" in building_name:
                building_name = building_name[:building_name.index("New")]
            if "NEW" in building_name:
                building_name = building_name[:building_name.index("NEW")]

            meter_path = building_path + '/' + obvius.to_pathname(metername)
            cf.add_section(meter_path)
            cf.set(meter_path, 'type', 'smap.drivers.obvius.bmo.BMOLoader')
            cf.set(meter_path, 'Metadata/Extra/MeterName', metername)
            cf.set(meter_path, 'Metadata/Instrument/Model', '"' + metertype + '"')
            cf.set(meter_path, 'Metadata/Location/Building', building_name)
            cf.set(meter_path, 'Url', url)

            # add any extra config options specific to this meter type
            map = sensordb.get_map(metertype, building_name)
            if 'extra' in map:
                for k,v in map['extra'].iteritems():
                    cf.set(meter_path, k, v)


    cf.write(sys.stdout)
#     else:
#         for k, v in conf.iteritems():
#             if len(v) > 1:
#                 for (meter, ) in v.iteritems():
#                     print '/' + obvius.to_pathname(k) + '/' + obvius.to_pathname(meter) + ',' + k + " " + meter
#             else:
#                 print '/' + obvius.to_pathname(k) + '/' + obvius.to_pathname(v.keys()[0]) + ',' + k

elif opts.db:
    print "generate sensordb"
    for location, devs in devices.iteritems():
        print devs
