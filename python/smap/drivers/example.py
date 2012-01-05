from smap.driver import SmapDriver
from smap.util import periodicSequentialCall

class Driver(SmapDriver):
    def setup(self, opts):
        self.add_timeseries('/sensor0', 'V')
        self.set_metadata('/sensor0', {
            'Instrument/ModelName' : 'ExampleInstrument'
            })
        self.counter = int(opts.get('StartVal', 0))

    def start(self):
		# Call read every 2 seconds
        periodicSequentialCall(self.read).start(2)

    def read(self):
        self.add('/sensor0', self.counter)
        self.counter += 1