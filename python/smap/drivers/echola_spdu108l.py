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
@author Michael Sankur <msankur@berkeley.edu>
"""

from smap import actuate, driver
from smap.util import periodicSequentialCall
import xmltodict
import requests

class ECHOLA_SPDU108L(driver.SmapDriver):
    
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.username = opts.get('username','admin')
        self.password = opts.get('password','admin')
        self.ip = opts.get('ip','192.168.1.109')
        self.rate = float(opts.get('rate', 1))
        
        self.readURL = 'http://' + self.ip + '/api.xml'
        self.actURL = 'http://' + self.ip + '/switch.cgi?out'
        
        ts = [None]*8
        for k in range(1,9):
            ts[k-1] = self.add_timeseries('/outlet' + str(k) + '/on', 'binary', data_type='long', timezone=self.tz)
            self.add_timeseries('/outlet' + str(k) + '/power', 'Watts', data_type='double', timezone=self.tz)
        self.add_timeseries('/unit_power', 'Watts', data_type='double', timezone=self.tz)
        
        print 'READ POINTS SET UP'
        
        for k in range(1,9):
            ts[k-1].add_actuator(OnOffActuator(outlet=k, readURL=self.readURL, actURL=self.actURL))
            
        print 'ACTUATOR POINTS SET UP'            

        self.set_metadata('/', {'Metadata/Device': 'General Controller',
                                'Metadata/Model': 'Echola SPDU 108L',
                                'Metadata/Driver': __name__})
        for k in range(1,9):
            self.set_metadata('/outlet{0}/on'.format(k), {'Metadata/Type': 'Reading'})
            self.set_metadata('/outlet{0}/power'.format(k), {'Metadata/Type': 'Reading'})
            self.set_metadata('/outlet{0}/power'.format(k), {'Metadata/Sensor': 'Energy'})
            self.set_metadata('/outlet{0}/on_act'.format(k), {'Metadata/Type': 'Command'})
        self.set_metadata('/unit_power',{'Metadata/Type': 'Reading'})
        self.set_metadata('/unit_power',{'Metadata/Sensor': 'Energy'})
        
    def start(self):
        # call self.read every self.rate seconds
        periodicSequentialCall(self.read).start(self.rate)

    def read(self):
        r = requests.get(self.readURL)
        data_xml = r.content.strip(" \r\n\t")
        data_dict = xmltodict.parse(data_xml).get('response')
        
        for k in range(1,9):
            self.add('/outlet' + str(k) + '/on', int(data_dict['pstate' + str(k)]))
            self.add('/outlet' + str(k) + '/power', float(data_dict['pow' + str(k)]))
        self.add('/unit_power', float(data_dict['powt']))
        
    
class EcholaActuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.outlet = opts.get('outlet')
        self.readURL = opts.get('readURL')
        self.actURL = opts.get('actURL')

    def get_state(self, request):
        r = requests.get(self.readURL)
        data_xml = r.content.strip(" \r\n\t")
        data_dict = xmltodict.parse(data_xml).get('response')
        return int(data_dict['pstate'+str(self.outlet)])
    
    def set_state(self, request, state):
        if state == 0 or state == 'off':
            state = 0
            requests.get(self.actURL + str(self.outlet) + '=0')
        if state == 1 or state == 'on':
            state = 1
            requests.get(self.actURL + str(self.outlet) + '=1')
        return state
            
class OnOffActuator(EcholaActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        EcholaActuator.__init__(self, **opts)
