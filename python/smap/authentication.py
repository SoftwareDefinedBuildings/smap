
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
