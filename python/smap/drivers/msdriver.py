import math, time, requests, json
from smap import driver, util, actuate

class VisibleEnergyMonoStripDriver(driver.SmapDriver):
    def setup(self, opts):
        self.url = opts.get("url")

        self.add_timeseries('/red/state', 'IO',data_type='long')
        self.set_metadata('/red/state', {'Description' : 'Red State'})
        self.add_timeseries('/red/power', 'W',data_type='double')
        self.set_metadata('/red/power', {'Description' : 'Red Power'})

        self.add_timeseries('/blue/state', 'IO',data_type='long')
        self.set_metadata('/blue/state', {'Description' : 'Blue State'})
        self.add_timeseries('/blue/power', 'W',data_type='double')
        self.set_metadata('/blue/power', {'Description' : 'Blue Power'})

        self.add_timeseries('/yellow/state', 'IO',data_type='long')
        self.set_metadata('/yellow/state', {'Description' : 'Yellow State'})
        self.add_timeseries('/yellow/power', 'W',data_type='double')
        self.set_metadata('/yellow/power', {'Description' : 'Yellow Power'})

        self.add_timeseries('/orange/state', 'IO',data_type='long')
        self.set_metadata('/orange/state', {'Description' : 'Orange State'})
        self.add_timeseries('/orange/power', 'W',data_type='double')
        self.set_metadata('/orange/power', {'Description' : 'Orange Power'})


        self.add_actuator('/red/state_act', 'On/Off', MonoBinaryActuator(color = 'Red', url=self.url))
        self.add_actuator('/orange/state_act', 'On/Off', MonoBinaryActuator(color = 'Orange', url=self.url))
        self.add_actuator('/yellow/state_act', 'On/Off', MonoBinaryActuator(color = 'Yellow', url=self.url))
        self.add_actuator('/blue/state_act', 'On/Off', MonoBinaryActuator(color = 'Blue', url=self.url))

    def start(self):
        util.periodicSequentialCall(self.read).start(10)

    def read(self):
        content = requests.get(self.url + '/status.js')
        jsonData = json.loads(content.content)
        for dev in jsonData['strip']['status']['socket']:
            if dev['name'] == 'Orange':
                self.add('/orange/state', time.time(), 1 if dev['state'] == 'ON' else 0)
                self.add('/orange/power', time.time(), dev['watts'])
            elif dev['name'] == 'Red':
                self.add('/red/state', time.time(), 1 if dev['state'] == 'ON' else 0)
                self.add('/red/power', time.time(), dev['watts'])
            elif dev['name'] == 'Yellow':
                self.add('/yellow/state', time.time(), 1 if dev['state'] == 'ON' else 0)
                self.add('/yellow/power', time.time(), dev['watts'])
            elif dev['name'] == 'Blue':
                self.add('/blue/state', time.time(), 1 if dev['state'] == 'ON' else 0)
                self.add('/blue/power', time.time(), dev['watts'])

positions = {
        'Red': '1',
        'Yellow': '2',
        'Orange': '0',
        'Blue': '3'
        }
class MonoStripActuator(actuate.SmapActuator):

        def __init__(self, **opts):
                print opts
                self.url = opts['url']
                self.color = opts['color']
                self.url = self.url + '/' + positions[self.color] 

        def get_state(self, request):
                print request
                content = requests.get(self.url + '/status.js')
                print content
                jsonData = json.loads(content.content)
                print jsonData['strip']['status']
                return 1 if jsonData['strip']['status']['socket'][0]['state'] == 'ON' else 0

        def set_state(self, request, st):
                print st
                if st == 0:
                        r = requests.get(self.url + '/set.js?value=off')
                        return 0
                if st == 1:
                        r = requests.get(self.url + '/set.js?value=on')
                        return 1
                #time.sleep(5)

class MonoBinaryActuator(MonoStripActuator, actuate.BinaryActuator):

        def __init__(self, **opts):
                actuate.BinaryActuator.__init__(self)
                MonoStripActuator.__init__(self, **opts)
