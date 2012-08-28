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

# default configuration 
SERVER = {
    'port' : 8080,
}

try:
    from twisted.internet import ssl
    from twisted.python import log

    from OpenSSL import SSL
    import os
except ImportError:
    def getSslContext():
        raise NotImplementedError()
else:
    def verifyCallback(connection, x509, errnum, errdepth, okay):
        if not okay:
            log.err("Invalid cert from subject: " + str(x509.get_subject()))
            return False
        return True

    def getSslContext(verify_clients=False, verify_callback=verifyCallback):
        if not 'key' in SERVER or not 'cert' in SERVER["cert"]:
            raise ValueError("Cannot create ssl context without key and certificate files")
    
        ctx_factory = ssl.DefaultOpenSSLContextFactory(os.path.expanduser(SERVER["key"]), 
                                                   os.path.expanduser(SERVER["cert"]))
        ctx = ctx_factory.getContext()
        if verify_clients: 
            ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                           verify_callback)
        if 'ca' in SERVER:
            ctx.load_verify_locations(os.path.expanduser(SERVER["ca"]))

        return ctx_factory
