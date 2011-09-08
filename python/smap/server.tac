# -*- python -*-

import os
from twisted.application import service, internet
from twisted.web import server

from server import getSite

def getWebService():
    """Return a service for creating an application
    """
    s = getSite()
    return internet.TCPServer(8080, s)
    
application = service.Application("sMAP Server")

service = getWebService()
service.setServiceParent(application)
