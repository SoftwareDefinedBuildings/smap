import requests
import json
import uuid as uuidlib

#This is not meant to be usable in the general case. It's just for the tests
class Ssstream(object):
    """Simple sMAP stream. Yes I know what the s in sMAP is for."""
    def __init__(self, instName="instrument0",instFullName="ssMAP instrument",srcFullName="simple sMAP source",
                 sensorName="sensor0",uuid=None,unitofTime="ms",unitofMeasure="furlongs",timezone="America/Los_Angeles",
                 readings=[], url=None, subkey=None):
        if uuid is None:
            uuid = str(uuidlib.uuid1())
        self.obj = {
          "/": {
            "Contents": [
              instName
            ],
            "Metadata": {
              "SourceName": srcFullName
            }
          },
          instName: {
            "Contents": [
              sensorName
            ], 
          },  
          "/%s/%s"%(instName,sensorName): {
            "uuid": uuid, 
            "Metadata": {
              "Instrument": {
                "ModelName": instFullName
              }
            }, 
            "Properties": {
              "UnitofTime": unitofTime, 
              "Timezone": timezone, 
              "UnitofMeasure": unitofMeasure, 
              "ReadingType": "long"
            }, 
            "Readings": readings
          }
        }
        self.defaultpath="/%s/%s"%(instName,sensorName)
        self.defaulturl=url
        self.defaultsubkey=subkey
        self.defaultuuid=uuid
        self.defaulttimeunit=unitofTime
    
    def set_readings(self, readings, path=None):
        if path is None: path = self.defaultpath
        self.obj[path]["Readings"] = readings
    
    def publish(self, url=None, subkey=None):    
        if url is None: url = self.defaulturl
        if subkey is None: subkey = self.defaultsubkey
        if url is None or subkey is None:
            raise ValueError("Both url and subscription key are required, no defaults found")
        url += "/add/%s" % subkey
        r = requests.post(url, headers={'Transfer-Encoding': 'chunked', 'Content-Type': 'application/json'},
                      data=(lambda:(yield(json.dumps(self.obj))))())
        return r.status_code == 200

    def get_readings(self, starttime, endtime, unit=None, url=None, uuid=None):
        if uuid is None: uuid=self.defaultuuid
        if unit is None: unit=self.defaulttimeunit
        if url is None: url=self.defaulturl
        url += "/api/data/uuid/%s?starttime=%d&endtime=%d&unit=%s" % (uuid,starttime,endtime,unit)
        r = requests.get(url)
        if r.status_code != 200: raise ValueError("Bad request. HTTP=%d"%r.status_code)
        return json.loads(r.text)[0]["Readings"]
    
    def query(self, qs, kd=None, url=None, subkey=None):
        if kd is None: kd = {}
        if url is None: url = self.defaulturl
        if subkey is None: subkey = self.defaultsubkey
        builtinkd = {"uuid":self.defaultuuid}  
        for k in builtinkd:
            if k not in kd.keys():
                kd[k] = builtinkd[k]               
        qryformat = qs.format(**kd)
        print "qryformat: ", qryformat
        url += "/api/query?"
        r = requests.post(url, headers={'Transfer-Encoding': 'chunked', 'Content-Type': 'application/text'},
                      data=(lambda:(yield(qryformat)))())
        if r.status_code != 200: raise ValueError("Bad query. HTTP=%d"%r.status_code)
        return json.loads(r.text)
          
        
        
        
        
        
        
        
        
        
        
        
