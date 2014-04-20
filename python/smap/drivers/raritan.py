import telnetlib
import os
import sys
import re
import cmd
from smap import actuate, driver
from smap.util import periodicSequentialCall

# TODO: put in some code to reconnect in the case of dead telnet session

CONSOLE_PROMPT='clp:/->'

class ConsoleClient(cmd.Cmd):
    """Simple Console Client in Python.  This allows for readline functionality."""

    def connect_to_console(self, host, port):
        """Can throw an IOError if telnet connection fails."""
        self.console = telnetlib.Telnet(host, port)
        self.console.read_until('Login:')
        self.console.write('admin\r\n')
        print 'login'
        self.console.read_until('Password:')
        print 'password'
        self.console.write('ucberkeley\r\n')
        print 'wait'
        self.status()

    def read_from_console(self):
        """Read from console until prompt is found (no more data to read)
        Will throw EOFError if the console is closed.
        """
        read_data = self.console.read_until(CONSOLE_PROMPT)
        return self.strip_console_prompt(read_data)

    def strip_console_prompt(self,data_received):
        """Strip out the console prompt if present"""
        if data_received.startswith(CONSOLE_PROMPT):
            return data_received.partition(CONSOLE_PROMPT)[2]
        else:
            #The banner case when you first connect
            if data_received.endswith(CONSOLE_PROMPT):
                return data_received.partition(CONSOLE_PROMPT)[0]
            else:
                return data_received

    def status(self):
        command = 'show -d properties=powerState /system1/outlet*'
        return self.run_console_command(command)

    def setstate(self, outletnum, state):
        if state == 1 or state == 'on':
            command = 'set /system1/outlet{0} powerState=on'.format(outletnum)
        elif state == 0 or state == 'off':
            command = 'set /system1/outlet{0} powerState=off'.format(outletnum)
        return self.run_console_command(command)

    def getstate(self, outletnum):
        command = 'show -d properties=powerState /system1/outlet'+str(outletnum)
        out = self.run_console_command(command)
        return out

    def run_console_command(self,line):
        self.console.write(line + '\r\n')
        data_recved = self.read_from_console()        
        return self.strip_console_prompt(data_recved)

    def do_EOF(self, line): 
        try:
            self.console.write("quit\n")
            self.console.close()
        except IOError:
            pass
        return True

    def do_help(self,line):
        """The server already has it's own help command.  Use that"""
        self.run_console_command("help\n")

    def do_quit(self, line):        
        return self.do_EOF(line)

    def default(self, line):
        """Allow a command to be sent to the console."""
        self.run_console_command(line)

    def emptyline(self):
        """Don't send anything to console on empty line."""
        pass


class Raritan(driver.SmapDriver):

    def setup(self, opts):
        self.tz = opts.get('Metadata/Timezone', None)
        self.username = opts.get('username','admin')
        self.password = opts.get('password','ucberkeley')
        self.ip = opts.get('ip','192.168.1.150')
        self.port = int(opts.get('port',23))
        self.console = ConsoleClient()
        self.console.connect_to_console(self.ip, self.port)
        self.rate = float(opts.get('rate', 1))
        self.add_timeseries('/outlet1/state', 'On/Off', data_type='long', timezone=self.tz)
        self.add_timeseries('/outlet2/state', 'On/Off', data_type='long', timezone=self.tz)
        self.add_timeseries('/outlet3/state', 'On/Off', data_type='long', timezone=self.tz)
        self.add_timeseries('/outlet4/state', 'On/Off', data_type='long', timezone=self.tz)
        self.add_timeseries('/outlet5/state', 'On/Off', data_type='long', timezone=self.tz)
        self.add_timeseries('/outlet6/state', 'On/Off', data_type='long', timezone=self.tz)

        self.add_actuator('/outlet1/state_act', 'On/Off', OnOffActuator(outlet=1, console=self.console))
        self.add_actuator('/outlet2/state_act', 'On/Off', OnOffActuator(outlet=2, console=self.console))
        self.add_actuator('/outlet3/state_act', 'On/Off', OnOffActuator(outlet=3, console=self.console))
        self.add_actuator('/outlet4/state_act', 'On/Off', OnOffActuator(outlet=4, console=self.console))
        self.add_actuator('/outlet5/state_act', 'On/Off', OnOffActuator(outlet=5, console=self.console))
        self.add_actuator('/outlet6/state_act', 'On/Off', OnOffActuator(outlet=6, console=self.console))


    def start(self):
        periodicSequentialCall(self.read).start(self.rate)

    
    def read(self):
        status = self.console.status()
        try:
            tmp = status.index('/system1/outlet*')
            newstates = status[tmp+len('/system1/outlet*'):].strip().split('\r\n\r\n')
        except:
            newstates = status
        for i,newstate in enumerate(newstates):
            if i >= 6: break
            source  = re.compile(r'(^[a-z/0-9]+)').findall(newstate)
            val = re.compile(r'powerState is ([12])').findall(newstate)
            if val:
                self.add('/outlet{0}/state'.format(i+1), int(val[0]))

class RaritanActuator(actuate.SmapActuator):
    def __init__(self, **opts):
        self.console = opts.get('console')
        self.outlet = opts.get('outlet')

    def get_state(self, request):
        return 0
        #return self.console.getstate(self.outlet)

    def set_state(self, request, state):
        return self.console.setstate(self.outlet, state)

class OnOffActuator(RaritanActuator, actuate.BinaryActuator):
    def __init__(self, **opts):
        actuate.BinaryActuator.__init__(self)
        RaritanActuator.__init__(self, **opts)

