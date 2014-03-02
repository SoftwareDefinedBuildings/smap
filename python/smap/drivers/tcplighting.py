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
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""
import os, requests, __builtin__
from smap import actuate, driver
from smap.util import periodicSequentialCall
from smap.contrib import dtutil
from requests.auth import HTTPDigestAuth
import json
import time

import requests
from urllib2 import quote, unquote
from lxml import etree

URL = 'http://192.168.1.178/'
POSTURL = 'http://192.168.1.178/gwr/gop.php'
headers = {"Content-Type": "text/xml"}

# 0: the command, e.g. GWRLogin, 1: the XML,
command = lambda x,y: quote('cmd={0}&data={1}&fmt=xml'.format(x, y)).replace('%26','&').replace('%3D','=').replace('/','%2F')

commands = {
    'GWRLogin': '<gip><version>1</version><email>admin</email><password>admin</password></gip>',
    'GatewayGetInfo': '<gip><version>1</version><token>{token}</token><fwnew>1</fwnew></gip>',
    'DeviceSendCommand': '<gip><version>1</version><token>{token}</token><did>{device_id}</did><value>{state}</value></gip>',
    'DeviceSendCommandLevel': '<gip><version>1</version><token>{token}</token><did>{device_id}</did><value>{state}</value><type>level</type></gip>',
    'Info': '<gwrcmds><gwrcmd><gcmd>SceneGetList</gcmd><gdata><gip><version>1</version><token>{token}</token><fields>activeonly,bigicon,detail,imageurl</fields><islocal>1</islocal></gip></gdata></gwrcmd></gwrcmds>',
    'State': '<gwrcmds><gwrcmd><gcmd>RoomGetCarousel</gcmd><gdata><gip><version>1</version><token>{token}</token><fields>name,image,imageurl,control,power,product,class,realtype,status</fields></gip></gdata></gwrcmd></gwrcmds>'
}

def get_token(posturl):
    resp = requests.post(posturl, headers=headers, data=command('GWRLogin',commands['GWRLogin']))
    xml = resp.content
    parsed = etree.fromstring(xml)
    token = parsed.xpath('//gip')[0].find('token').text
    return token

def get_serverinfo(posturl, token):
    resp = requests.post(posturl, headers=headers, data=command('GatewayGetInfo',commands['GatewayGetInfo'].format(token=token)))
    xml = resp.content
    parsed = etree.fromstring(xml)
    gateway_id = parsed.find('gateway').find('gid').text
    framework_version = parsed.find('gateway').find('fwversion').text
    serial_number = parsed.find('gateway').find('serial').text
    return gateway_id, framework_version, serial_number

def set_state(posturl, token,device_id,state):
    xmldata = commands['DeviceSendCommand'].format(token=token,device_id=device_id,state=state)
    resp = requests.post(posturl, headers=headers, data=command('DeviceSendCommand',xmldata))
    xml = resp.content
    parsed = etree.fromstring(xml)

def set_level(posturl, token,device_id,state):
    xmldata = commands['DeviceSendCommandLevel'].format(token=token,device_id=device_id,state=state)
    resp = requests.post(posturl, headers=headers, data=command('DeviceSendCommand',xmldata))
    xml = resp.content
    parsed = etree.fromstring(xml)

def get_states(posturl, token):
    resp = requests.post(posturl, headers=headers, data=command('GWRBatch', commands['State'].format(token=token)))
    xml = resp.content
    parsed = etree.fromstring(xml)
    devices = parsed.xpath('//device')
    device_ids = [x.find('did').text for x in devices]
    states = [x.find('state').text for x in devices]
    power = [x.find('power').text for x in devices]
    levels = map(lambda x: x.text, filter(lambda x: x is not None, [x.find('level') for x in devices]))
    return zip(device_ids, states, power, levels)

def get_deviceinfo(posturl, token):
    resp = requests.post(posturl, headers=headers, data=command('GWRBatch',commands['Info'].format(token=token)))
    xml = resp.content
    parsed = etree.fromstring(xml)
    devices = parsed.xpath('//device')
    device_ids = [x.find('id').text for x in devices]
    readings = [x.findall('cmd') for x in devices]
    values = [int(x[0].getchildren()[1].text) for x in readings]
    levels = [int(x[1].getchildren()[1].text) for x in readings]
    return zip(device_ids, values, levels)

class TCP(driver.SmapDriver):
    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.ip = opts.get('ip', None)
        self.readrate = int(opts.get('readrate', 5))
        self.posturl = 'http://{0}/gwr/gop.php'.format(self.ip)
        self.token = get_token(self.posturl)
        self.gateway_id, self.framework_version, self.serial_number = get_serverinfo(self.posturl, self.token)
        devices = get_states(self.posturl, self.token)
        for device in devices:
            self.add_timeseries('/'+str(device[0])+'/state', 'On/Off', data_type='long', timezone=self.tz)
            self.add_timeseries('/'+str(device[0])+'/power', 'V', data_type='double', timezone=self.tz)
            self.add_timeseries('/'+str(device[0])+'/level', 'Brightness', data_type='long', timezone=self.tz)
            self.add_actuator('/'+str(device[0])+'/state_act', 'On/Off', OnOffActuator(ip=self.ip, device_id=str(device[0])))
            self.add_actuator('/'+str(device[0])+'/level_act', 'Brightness', BrightnessActuator(ip=self.ip, device_id=str(device[0]), range=(0,100)))

    def start(self):
        periodicSequentialCall(self.read).start(self.readrate)

    def read(self):
        devices = get_states(self.posturl, self.token)
        for device in devices:
            print '/'+str(device[0])+'/state'
            self.add('/'+str(device[0])+'/state',int(device[1]))
            self.add('/'+str(device[0])+'/power',float(device[2]))
            level = int(device[3]) if int(device[1]) else 0
            self.add('/'+str(device[0])+'/level',level)

class TCPLActuator(actuate.SmapActuator):

    def __init__(self, **opts):
        self.ip = opts.get('ip', None)
        self.posturl = 'http://{0}/gwr/gop.php'.format(self.ip)
        self.token = get_token(self.posturl)
        self.device_id = opts.get('device_id')

    def get_state(self, request):
        states = get_states(self.posturl, self.token)
        return [int(x[1]) for x in states if x[0] == self.device_id][0]

class OnOffActuator(TCPLActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        TCPLActuator.__init__(self, **opts)

    def set_state(self, request, state):
        set_state(self.posturl, self.token, self.device_id, state)
        return int(state)

class BrightnessActuator(TCPLActuator, actuate.ContinuousIntegerActuator):
    def __init__(self, **opts):
        actuate.ContinuousIntegerActuator.__init__(self, opts['range'])
        TCPLActuator.__init__(self, **opts)

    def set_state(self, request, state):
        print request, state
        if int(state) > 100:
            state = 100
        elif int(state) < 0:
            state = 0
        set_level(self.posturl, self.token, self.device_id, state)
        return int(state)

