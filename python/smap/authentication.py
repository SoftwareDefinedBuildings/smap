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

import core

authdb = {
    'client certificate' : set(['CAP_SECURE']),

    # all clients who have authenticated (basically, have a valid cert) have this extra capability
    '__authenticated__' : set(['CAP_AUTHENTICATED']),

    # all clients who connect over ssl have this capability
    '__has_ssl__' : set(['CAP_HAS_SSL']),

    # all clients have these
    '*' : set(['CAP_UNSEC_READ'])
    }

class Auth:
    """This class wraps up checking principals' capabilities.  All
    clients have the capability CAP_UNSEC_READ; for other capabilities
    we must look up the principal in an authorization database.

    The principal's identity must be verified through other means; the
    only method supported at this point is via SSL client
    certificates.
    """
    def __init__(self, clist):
        self.clist = set(clist)

    def ssl_get_principal(request):
        print "request_ssl_get_principal"
        print dir(request.transport)

    def has_cap(self, request, principal):
        # the reporting system bypasses checks
         #print self.ssl_get_principal(request)
        if principal == '__reporting__':
            return True
        # check caps for all clients
        elif not self.clist.isdisjoint(authdb['*']):
            return True
        # check if only ssl is required
        elif request.isSecure() and \
             not self.clist.isdisjoint(authdb['__has_ssl__']):
            return True
        # check extra caps for authenticated clients
        elif principal != None and \
                 not self.clist.isdisjoint(authdb['__authenticated__']):
            return True
        # check caps specific to this principal
        elif principal != None and \
                 not self.clist.isdisjoint(authdb.get(principal, set([]))):
            return True
        # otherwise reject
        else:
            return False
        

class authenticated:
    """decorator """
    def __init__(self, clist):
        self.auth = Auth(clist)

    def __call__(self, f):
        def wrapped_f(*args, **kwargs):
            if self.auth.has_cap(args[1], getattr(args[1], 'principal', None)):
                return f(*args, **kwargs)
            else:
                raise core.SmapException("Permission denied", 403)
        return wrapped_f
