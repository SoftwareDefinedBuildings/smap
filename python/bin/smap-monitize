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
"""
Make a smap config file ready to be run from monit
"""

import sys
import os
from commands import getoutput
from pwd import getpwnam
from optparse import OptionParser
from configobj import ConfigObj

try:
    import ordereddict
except ImportError:
    import collections as ordereddict


parser = OptionParser()
parser.add_option('-v', '--var', dest='var',
                  default='/var/smap',
                  help="var directory")
parser.add_option('-m', '--monit-d', dest='monit_d',
                  default='/etc/monit/conf.d/',
                  help='monit service directory')
parser.add_option('-s', '--smap-d', dest='smap_d',
                  default='/etc/smap/',
                  help='directory for smap configurations')
parser.add_option('-u', '--uid', dest='user',
                  default='smap',
                  help='user to run as')
parser.add_option('-t', '--twistd', dest='twistd',
                  default=None,
                  help='path of twistd version to use')
parser.add_option('-f', '--force', dest='force',
                  default=False, action='store_true',
                  help='force overwrite of existing files')
parser.add_option('-e', '--env', dest='env',
                  default='',
                  help='comma-separated list of environment variables to preserve')
parser.add_option('-c', '--cwd', dest='cwd',
                  default=None,
                  help='directory name to set as the cwd')
opts, args = parser.parse_args()

ports = set()

try:
    uid, gid = getpwnam(opts.user)[2:4]
except KeyError:
    print >>sys.stderr, "Warning: user %s not found; using current user" % opts.user
    uid, gid = os.getuid(), os.getgid()
except OSError, e:
    print >>sys.stderr, "Error finding uid for %s: %s" % (opts.user, str(e))
    sys.exit(1)

if not opts.twistd:
    opts.twistd = getoutput("which twistd")
    if opts.twistd == '':
        print >>sys.stderr, "Could not find twistd!"
        sys.exit(1)

if not os.path.exists(opts.var):
    try:
        os.makedirs(opts.var)
    except OSError, e:
        print >>sys.stderr, "Error creating %s: %s" % (opts.var, str(e))
        sys.exit(1)

if not os.access(opts.var, os.W_OK | os.X_OK):
    print >>sys.stderr, "Cannot write to %s or is not a dir -- check permissions" % opts.var
    sys.exit(1)

if not os.access(opts.monit_d, os.W_OK | os.X_OK):
    print >>sys.stderr, "Cannot access monit config directory: %s" % opts.monit_d
    sys.exit(1)

if not os.access(opts.smap_d, os.W_OK | os.X_OK):
    print >>sys.stderr, "Cannot access smap config directory: %s" % opts.smap_d
    sys.exit(1)

def build_env(opts):
    rv = ''
    for ev in opts.env.split(','):
        val = os.getenv(ev)
        if not val: continue
        if ev.endswith('PATH'):
            val = ':'.join(map(os.path.abspath, val.split(':')))
        rv += "export %s=%s\n" % (ev, val)
    return rv

for conffile in args:
    root = os.path.basename(conffile[:conffile.rfind('.')])
    print "processing", root, "...",
    datadir = os.path.join(opts.var, root)
    if not os.path.exists(datadir):
        os.mkdir(datadir)
        os.chown(datadir, uid, gid)
    
    conf = ConfigObj(conffile, indent_type='  ')
    if not 'server' in conf:
        conf['server'] = {}

    # set the data directory
    conf["server"]["DataDir"] = os.path.abspath(datadir)
    if not ('port' in conf["server"] or 'Port' in conf['server']):
        print
        print "Skipping", root, ": no port in conf"
        continue
    else:
        p = conf["server"].get('Port', conf['server'].get("port"))
        print "port", p
        if p in ports:
            print "Detected port conflict on port", p
            print " .. skipping", root
            continue
        else:
            ports.add(p)

    # write the conf and make it owned by the right user to make sure
    # it can be read.
    newconf = os.path.join(opts.smap_d, root + '.ini')
    with open(newconf, 'w') as fp:
        conf.write(fp)
    os.chown(newconf, uid, gid)
    os.chmod(newconf, 0444)

    pidfile = os.path.abspath(os.path.join(datadir, "twistd.pid"))
    logfile = os.path.abspath(os.path.join(datadir, "twistd.log"))
    newsh = os.path.abspath(os.path.join(opts.smap_d, root + ".sh"))
    with open(newsh, "w") as fp:
        fp.write("""#!/bin/sh
cd %(cwd)s
%(env)s
%(twistd)s --logfile=%(logfile)s  \\
            --pidfile=%(pidfile)s smap %(conf)s
""" % {
                'cwd' : os.path.abspath(opts.cwd if opts.cwd else datadir),
                'env' : build_env(opts),
                'twistd' : opts.twistd,
                'logfile' : logfile,
                'pidfile' : pidfile,
                'conf': os.path.join(os.path.abspath(opts.smap_d), root + '.ini')
                })
    os.chown(newsh, uid, gid)
    os.chmod(newsh, 0744)

    # write out a monit service definition 
    mpath = os.path.join(opts.monit_d, root)
    if os.path.exists(mpath) and not opts.force:
        print >>sys.stderr, "Monit service exists, not overwriting (use -f):", mpath
        continue

    with open(mpath, "w") as fp:
        print >>fp, "check process %s pidfile %s" % (root, pidfile)
        print >>fp, "\tstart program = \"%s\" as uid %i and gid %i with timeout 120 seconds" % (newsh, uid, gid)
        print >>fp, "\tstop program = \"/bin/sh -c '/bin/kill $(cat %s)'\"" % pidfile
        print >>fp, "\tgroup smap"
        print >>fp, "\tif failed host localhost port %s protocol http" % p
        print >>fp, "\t\tand request \"/data\""
        print >>fp, "\t\twith timeout 20 seconds for 2 cycles"
        print >>fp, "\tthen restart"
