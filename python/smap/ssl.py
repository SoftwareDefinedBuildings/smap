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
Configure client and server SSL contexts for use in various servers

@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import os
from twisted.python import log
from smap.util import to_bool

try:
    from twisted.internet.ssl import ClientContextFactory
    from twisted.internet.ssl import DefaultOpenSSLContextFactory
    from OpenSSL import SSL
except ImportError:
    pass
else:
    def defaultVerifyCallback(connection, x509, errnum, errdepth, okay):
        if not okay:
            log.err("Invalid cert from subject: " + str(x509.get_subject()))
            return False
        return True

    class SslServerContextFactory(DefaultOpenSSLContextFactory):
        """A server context factory for validating client connections"""
        def __init__(self, opts, verifyCallback=defaultVerifyCallback):
            if not 'key' in opts or not 'cert' in opts:
                raise ValueError("Cannot create ssl context without key and certificate files")

            DefaultOpenSSLContextFactory.__init__(self, 
                                                  os.path.expanduser(opts["key"]), 
                                                  os.path.expanduser(opts["cert"]))
            ctx = self.getContext()
            if 'verify' in opts and to_bool(opts['verify']):
                ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                               verifyCallback)
            if 'ca' in opts:
                ctx.load_verify_locations(os.path.expanduser(opts["ca"]))


    class SslClientContextFactory(ClientContextFactory):
        """Make a client context factory for delivering data.
        """
        def __init__(self, opts, verifyCallback=defaultVerifyCallback):
            self.ssl_opts = opts
            self.verifyCallback = verifyCallback

        def getContext(self, hostname, port): 
            self.method = SSL.SSLv23_METHOD
            ctx = ClientContextFactory.getContext(self)

            if 'cert' in self.ssl_opts and 'key' in self.ssl_opts:
                ctx.use_certificate_file(os.path.expanduser(self.ssl_opts['cert']))
                ctx.use_privatekey_file(os.path.expanduser(self.ssl_opts['key']))

            if 'verify' in self.ssl_opts and to_bool(self.ssl_opts['verify']):
                ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                               self.verifyCallback)
            if 'ca' in self.ssl_opts:
                ctx.load_verify_locations(os.path.expanduser(self.ssl_opts['CAFile']))

            return ctx


