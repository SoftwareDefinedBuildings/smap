"""
Copyright (c) 2014, University of Southern Denmark
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
Driver for polling of z-wave devices connected to a RaZberry/RaspberryPI using the RaZberry REST API (http://razberry.z-wave.me). 
The driver automatically identifies connected devices and registers them.

Known limitations: Require restart if additional z-wave devices are added and does not support actuation of z-wave devices.
"""
"""
@author Mikkel Baun Kjaergaard <mbkj@mmmi.sdu.dk>
"""
import time
import json
import urllib2
from smap import driver, util

class RazBerry(driver.SmapDriver):
    """Generic base class for polling of z-wave devices connected to a RaZberry/RaspberryPI using the RaZberry REST API (http://razberry.z-wave.me)"""

    ip = "127.0.0.1"
    readrate = 30 #Hint: At lower read rates (1-10 seconds) the RazBerry module have been experienced to become unstable.

    def getDevices(self,jsondata):
        """Get list of z-wave devices from json data from the RaZberry REST API"""
        return jsondata["devices"].keys()

    def getDeviceDescription(self,jsondata,deviceid):
        """Generate a sensor description of a z-wave device from json data from the RaZberry REST API"""
        vendor = jsondata["devices"][deviceid]["data"]["vendorString"]["value"]
        devicetype = jsondata["devices"][deviceid]["data"]["deviceTypeString"]["value"]    
        return "%s - %s - %s" % (deviceid,devicetype,vendor)  

    def updateSensorValues(self,jsondata):
        """poll values from the RaZberry REST API"""
        devices = self.getDevices(jsondata)    
        for deviceid in devices:
            for commandClass in ["49","48","128","50"]:
                if commandClass in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                    try:
                        response = urllib2.urlopen('http://' + self.ip + ':8083/ZWaveAPI/Run/devices[' + deviceid + '].instances[0].commandClasses[' + commandClass + '].Get()')                
                    except urllib2.HTTPError, e:
                        print "HTTPError - updateSensorValues: " + str(e)
                    except urllib2.URLError, e:
                        print "URLError - updateSensorValues: " + str(e)
                    except httplib.HTTPException, e:
                        print "HTTPException - updateSensorValues: " + str(e)

    def readSensorValues(self,jsondata):
        """Interprete json data from the RaZberry REST API"""
        sensors = []
        devices = self.getDevices(jsondata)
    
        for deviceid in devices:
            devicedescription = self.getDeviceDescription(jsondata,deviceid)
                                   
            #SensorMultilevel        
            if "49" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["1","3","4","5","17"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"]:
                        sensortype = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"][sensorid]["sensorTypeString"]["value"]
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        time = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"][sensorid]["val"]["updateTime"]
                        value = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"][sensorid]["val"]["value"]
                        sensors.append({ "name": name, "time" : time, "value" : value})
                            
            #SensorBinary 
            if "48" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["1"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"]:
                        sensortype = "SensorBinary " + jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"][sensorid]["sensorTypeString"]["value"]
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        time = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"][sensorid]["level"]["updateTime"]
                        value = (1 if (jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"][sensorid]["level"]["value"]) else 0)
                        sensors.append({ "name": name, "time" : time, "value" : value})                    
        
            #Meter
            if "50" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["0","2"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"]:
                        sensortype = "Meter " + jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"][sensorid]["sensorTypeString"]["value"]
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        time = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"][sensorid]["val"]["updateTime"]
                        value = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"][sensorid]["val"]["value"]                    
                        sensors.append({ "name": name, "time" : time, "value" : value})

            #Battery Powered Device        
            if "128" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                sensordescription = devicedescription + " - Battery"
                name = "/" + sensordescription.replace(' ', '')
                time = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["128"]["data"]["last"]["updateTime"]
                value = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["128"]["data"]["last"]["value"]
                sensors.append({ "name": name, "time" : time, "value" : value})

        return sensors

    def getSensorDescriptions(self,jsondata):
        """Generate smap sensor descriptions from json data from the RaZberry REST API"""
        sensors = []
        devices = self.getDevices(jsondata)
    
        for deviceid in devices:
            devicedescription = self.getDeviceDescription(jsondata,deviceid)
                                   
            #SensorMultilevel        
            if "49" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["1","3","4","5","17"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"]:
                        sensortype = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"][sensorid]["sensorTypeString"]["value"]
                        scale = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["49"]["data"][sensorid]["scaleString"]["value"]
            
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        sensors.append({ "name": name, "scale": scale, "description" : sensordescription})
                            
            #SensorBinary 
            if "48" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["1"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"]:
                        sensortype = "SensorBinary " + jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["48"]["data"][sensorid]["sensorTypeString"]["value"]
                        scale = "Event"
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        sensors.append({ "name": name, "scale": scale, "description" : sensordescription})
            #Meter
            if "50" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                for sensorid in ["0","2"]:
                    if sensorid in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"]:
                        sensortype = "Meter " + jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"][sensorid]["sensorTypeString"]["value"]
                        scale = jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]["50"]["data"][sensorid]["scaleString"]["value"]
                        sensordescription = devicedescription + " - " + sensortype
                        name = "/" + sensordescription.replace(' ', '')
                        sensors.append({ "name": name, "scale": scale, "description" : sensordescription})
        
            #Battery Powered Device        
            if "128" in jsondata["devices"][deviceid]["instances"]["0"]["commandClasses"]:
                sensordescription = devicedescription + " - Battery"
                name = "/" + sensordescription.replace(' ', '')
                sensors.append({ "name": name, "scale": "%", "description" : sensordescription})
            
        return sensors


    def setup(self, opts):
        self.ip = opts.get('ip', self.ip)
        self.readrate = int(opts.get('readrate', self.readrate))
        self.tz = opts.get('Metadata/Timezone', None)

        response = urllib2.urlopen('http://' + self.ip + ':8083/ZWaveAPI/Data/0')
        self.jsondata = json.loads(response.read())        
        sensors = self.getSensorDescriptions(self.jsondata) 

        for sensor in sensors:
            print "Adding: " + str(sensor)
            self.add_timeseries(sensor["name"].encode('ascii', 'ignore'), sensor["scale"].encode('ascii', 'ignore'), data_type='double', timezone=self.tz)
            self.set_metadata(sensor["name"].encode('ascii', 'ignore'), {'Instrument/RazBerry' : sensor["description"].encode('ascii', 'ignore')})

    def start(self):
        util.periodicSequentialCall(self.read).start(self.readrate)

    def read(self):
        self.updateSensorValues(self.jsondata)

        try:
            response = urllib2.urlopen('http://' + self.ip + ':8083/ZWaveAPI/Data/0')        
            self.jsondata = json.loads(response.read())
            sensorvalues = self.readSensorValues(self.jsondata)
            
            for sensor in sensorvalues:
                self.add(sensor["name"],sensor["time"],float(sensor["value"]))
                
        except urllib2.HTTPError, e:
            print "HTTPError - read: " + str(e)
        except urllib2.URLError, e:
            print "URLError - read: " + str(e)
        except httplib.HTTPException, e:
            print "HTTPException - read: " + str(e)


