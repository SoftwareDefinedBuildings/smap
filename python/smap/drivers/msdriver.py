import math, time, requests, json
from smap import driver, util, actuate

class VisibleEnergyMonoStripDriver(driver.SmapDriver):
    def setup(self, opts):
	self.devname = opts.get("devname")
	self.url = opts.get("url")

        self.add_timeseries('/state', 'IO',data_type='long')
        self.set_metadata('/state', {'Description' : self.devname + ' State'})
	self.add_timeseries('/power', 'W',data_type='double')
        self.set_metadata('/power', {'Description' : self.devname + ' Power'})
	self.add_timeseries('/priority', 'Integer',data_type='long')
        self.set_metadata('/priority', {'Description' : self.devname + ' Priority'})


	#setup={'devname':self.devname, 'url':self.url, 'outlet':0}
	#act = BinaryActuator(**setup)
	#self.add_actuator('/outlet0/state/', 'On/Off', MonoStripActuator(devname = self.devname, url=self.url))
	self.add_actuator('/outlet0/state/', 'On/Off', MonoBinaryActuator(devname = self.devname, url=self.url))

    def start(self):
        util.periodicSequentialCall(self.read).start(10)

    def read(self):
	content = requests.get(self.url + '/status.js')
	jsonData = json.loads(content.content)
	print self.devname + '\n'
	#print jsonData
	print jsonData['strip']['status']['socket'][0]['watts']

	if jsonData['strip']['status']['socket'][0]['state'] == 'ON':
		self.add('/state', time.time(), 1)
	if jsonData['strip']['status']['socket'][0]['state'] == 'OFF':
		self.add('/state', time.time(), 0)
	self.add('/power', time.time(), (float(jsonData['strip']['status']['socket'][0]['watts'])))

class MonoStripActuator(actuate.SmapActuator):

	def __init__(self, **opts):
		self.url = opts['url']
    		self.devname = opts['devname']

#	def setup(self,opts):
#		self.devname = opts.get("devname")
#		self.url = opts.get("url")
#		actuate.BinaryActuator.setup(self, opts)

	def get_state(self, request):
		content = requests.get(self.url + '/0/status.js')
		jsonData = json.loads(content.content)
		if jsonData['strip']['status']['socket'][0]['state'] == 'ON':
			return 1
		if jsonData['strip']['status']['socket'][0]['state'] == 'OFF':
			return 0

	def set_state(self, request, st):
		if st == 0:
			r = requests.get(url + '/0/set.js?value=off')
		if st == 1:
			r = requests.get(url + '/0/set.js?value=on')
		#time.sleep(5)

class MonoBinaryActuator(MonoStripActuator, actuate.BinaryActuator):

    	def __init__(self, **opts):
        	actuate.BinaryActuator.__init__(self)
        	MonoStripActuator.__init__(self, **opts)
