
import uuid
import ConfigParser

try:
    import ordereddict
except ImportError:
    import collections as ordereddict

import core
import util
import driver
import smapconf

class SmapLoadError(core.SmapException):
    """An error was encountered loading a config file"""

def _save_path(conf, inst, path):
    conf.add_section(path)
    cur = inst.lookup(path)

    if not path in inst.drivers:
        conf.set(path, "type", cur.__class__.__name__)
    else:
        # if it's a driver, save the class name that it's loaded as
        conf.set(path, "type", inst.drivers[path].driver.__class__.__module__ + \
                     '.' + inst.drivers[path].driver.__class__.__name__)

    if hasattr(cur, "key"):
        conf.set(path, "key", getattr(cur, "key"))
    elif 'uuid' in cur:
        conf.set(path, "uuid", cur['uuid'])

    if conf.get(path, "type") == "Timeseries":
        conf.set(path, "BufferSize", str(cur['Readings'].size))

    for k, v in cur.iteritems():
        if k in ['uuid', 'Readings', 'Proxy', 'Contents']: continue
        for (name, value) in  util.buildkv(k, v):
            conf.set(path, name, value)

def dump(inst, file):
    """Dump an existing :py:class:`~smap.core.SmapInstance` object to a conf file

:param smap.Core.SmapInstance inst: the object to dump
:param string file: config filename
:raises IOError: if writing to the file fails
"""
    conf = ConfigParser.ConfigParser('', ordereddict.OrderedDict)
    conf.optionxform = str

    q = ['/']
    while len(q) > 0:
        cur = inst.get_collection(q[0])
        if cur and cur.has_key('Contents') and not q[0] in inst.drivers:
            for child in cur['Contents']:
                q.append(util.norm_path(q[0] + '/' + child))
        _save_path(conf, inst, q[0])

        if conf.get(q[0], 'type') == 'Timeseries':
            for k, v in core.Timeseries.DEFAULTS.iteritems():
                if conf.has_option(q[0], k) and \
                        conf.get(q[0], k) == str(v):
                    conf.remove_option(q[0], k)

        q.pop(0)

    with open(file, 'w') as fp:
        conf.write(fp)

def load(file, **instargs):
    """Create a sMAP instance based on the representation stored in a file.

The configuration file contains sections which refer to either
reporting instances, or paths in the sMAP heirarchy.  Any section
whose name starts with ``/`` is treated as a resource name; sections
starting with ``report`` are treated as reports.

The file must contain at least one section named ``/``, which must
contain a ``uuid`` key to set the root identifier for the source.

:param string file: filename of the configuration file
:param instargs: arguments passed to the :py:class:`~smap.core.SmapInstance` constructor.
:return smap.core.SmapInstance: the created instancev
:raise smap.loader.SmapLoadError: an error is encountered processing the file
:raise smap.core.SmapError: some other error is encountered validating the loaded object 
    """
    conf = ConfigParser.ConfigParser('', ordereddict.OrderedDict)
    conf.optionxform = str
    conf.read(file)

    # if there's a server section, override the default server
    # configuration with that
    if conf.has_section('server'):
        server_conf = dict([(k.lower(), v) for (k,v) in conf.items('server')])
        smapconf.SERVER = util.dict_merge(smapconf.SERVER, server_conf)

    # we need the root to have a uuid
    inst = core.SmapInstance(conf.get('/', 'uuid'), **instargs)
    inst.loading = True
    reports = []

    for s in conf.sections():
        print "Loading section", s
        if s.startswith('report'):
            if conf.has_option(s, 'ReportResource'):
                resource = conf.get(s, 'ReportResource')
            else:
                resource = '/+'
            dest = [conf.get(s, 'ReportDeliveryLocation')]
            for i in xrange(0, 10):
                if conf.has_option(s, 'ReportDeliveryLocation%i' % i):
                    dest.append(conf.get(s, 'ReportDeliveryLocation%i' % i))

            reportinst = {
                'ReportDeliveryLocation' : dest,
                'ReportResource' : resource,
                'uuid' : inst.uuid(s),
                }
            for o in ['MinPeriod', 'MaxPeriod']:
                if conf.has_option(s, o):
                    reportinst[o] = conf.getint(s, o)
            reports.append(reportinst)
            continue
        elif not s.startswith('/'):
            # path sections must start with a '/'
            # other sections might be present and could be parsed by
            # other parts of the program
            print "Warning: skipping section", s, "since it does not begin with a '/'"
            continue
        s = util.norm_path(s)

        # build the UUID for the item
        props = util.build_recursive(dict(conf.items(s)))
        id = None
        if conf.has_option(s, 'uuid'):
            key = None
            id = uuid.UUID(conf.get(s, 'uuid'))
        elif conf.has_option(s, 'key'):
            key = conf.get(s, 'key')
        else:
            # default to the path if 
            key = s
        if key:
            id = inst.uuid(key)
            # raise SmapLoadError("Every config file section must have a uuid or a key!")

        # create the timeseries or collection
        if s == '/' or \
               (conf.has_option(s, 'type') and conf.get(s, "type") == 'Collection') or \
               inst.get_collection(s) != None:
            if s == '/':
                c = inst.get_collection('/')
            elif inst.get_collection(s) != None:
                # sometimes you will have collections created twice,
                # for instance if a driver creates it and then we want
                # to tag it with metadata
                c = inst.get_collection(s)
            else:
                c = core.Collection(s, inst)
                inst.add_collection(s, c)
        elif not conf.has_option(s, 'type') or conf.get(s, "type") == "Timeseries":
            try:
                props['Properties']['UnitofMeasure']
            except KeyError:
                raise SmapLoadError("A Timeseries must have at least the Propertes/UnitofMeasure key")

            # the Timeseries uses defaults if the conf file doesn't
            # contain the right sections.
            c = core.Timeseries(id, props['Properties']['UnitofMeasure'],
                                data_type=props['Properties'].get('ReadingType', 
                                                                  core.Timeseries.DEFAULTS['Properties/ReadingType']),
                                timezone=props['Properties'].get('Timezone', 
                                                                 core.Timeseries.DEFAULTS['Properties/Timezone']),
                                buffersz=int(props.get('BufferSize', core.Timeseries.DEFAULTS['BufferSize'])))
            inst.add_timeseries(s, c)
        else:
            if not id:
                raise SmapLoadError("A driver must have a key or uuid to generate a namespace")
            
            # load a new driver manager layer
            newdrv = driver.SmapDriver.get_driver(inst, conf.get(s, 'type'), s, id)
            # create a collection and add it at the attachment point
            c = inst.get_collection(s)
            if not c:
                c = core.Collection(s, inst)
                inst.add_collection(s, c)

            # get the driver to add its points
            newdrv.setup(dict(conf.items(s)))

        # Metadata and Description are shared between both Collections
        # and Timeseries
        if props.has_key('Metadata'):
            # the driver may have added metadata; however config file
            # metadata overrides it
            c['Metadata'] = util.dict_merge(c.get('Metadata', {}),
                                            props['Metadata'])
        if props.has_key('Description'):
            c['Description'] = props['Description']
        if key:
            setattr(c, 'key', key)

    # since the sections could come in any order, update the reporting
    # instance to make sure all the topics are set right.
    for reportinst in reports:
        if not inst.reports.update_report(reportinst):
            inst.reports.add_report(reportinst)
    inst.reports.update_subscriptions()
    inst.loading = False
    return inst
