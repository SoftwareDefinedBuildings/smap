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

import time
import operator

from smap import core
from smap.archiver.data import escape_string
from smap.archiver import settings

"""object representing a client's permission.
"""

def build_authcheck(request, ti='', forceprivate=False, action=None):
    """Build an SQL WHERE clause which enforces access restrictions.
    Will pull any credentials out of the request object passed in.

    "action" should either be None, in which case the subscription
    permissions will be used, or one of the can_XXX permissions in the
    permission table.
    """
    query = "sub.id = s.subscription_id AND "
    if not 'private' in request.args and not forceprivate:
        query += "(sub%s.public " % ti
    else:
        query += "(false "

    if 'key' in request.args:
        query += 'OR ( (' + ' OR '.join(["sub.key = %s" % escape_string(x + ti)
                                      for x in request.args['key']]) + \
                                       ') )'

    if (settings.conf['features']['permissions'] and 
        'key' in request.args and action is not None):
        # add permissions granted by the permissions table
        query += """OR ( (sub.id IN (SELECT perm_sub.subscription_id 
FROM permission perm, permission_subscriptions perm_sub
WHERE perm.id = perm_sub.permission_id AND 
 ((perm.valid_after IS NULL OR perm.valid_after < current_timestamp) AND
  (perm.valid_until IS NULL or perm.valid_until > current_timestamp)) AND (""" + \
            ' OR '.join(('perm.key = %s' % escape_string(x + ti)
                         for x in request.args['key'])) + \
                         (') AND perm.can_%s IS true)' % action) + \
                         ') AND sub.id = s.subscription_id)'

    query += ")"
    return query

class QueryException(core.SmapException):
    pass
