
import sys
import re
import pprint
from BeautifulSoup import BeautifulSoup as bs
from httputils import load_html
from optparse import OptionParser
import ConfigParser
import urllib

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
    (opts, args) = parser.parse_args()
    opts.conf = True
    if opts.types or opts.buildings:
        opts.conf = False

    # find all the AcquiSuite boxes
    devices = {}
    soup = load_html(BMOROOT + STATUSPAGE, AUTH=AUTH, cache=opts.cache)
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
            print "Processing", location
        soup = load_html(BMOROOT + devices[location]['href'], AUTH=AUTH, cache=opts.cache)
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
        for v in devices.itervalues():
            for t in v['subdevices']:
                mtypes[t['type']] = mtypes.get(t['type'], 0) + 1
        for n, c in mtypes.iteritems():
            print c, n

    if opts.buildings:
        print '\n'.join(devices.iterkeys())

if opts.conf:
    def make_section(cmps):
        cmps = map(lambda s: s.replace(' ', '_'), cmps)
        return '/' + '/'.join(map(lambda s: urllib.quote(s, safe=''), cmps))

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
            print d
            if d['type'] in sensordb.TYPES:
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
