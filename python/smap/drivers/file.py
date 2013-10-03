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

import os

from smap import actuate, driver
from smap.authentication import authenticated

class _Actuator(actuate.SmapActuator):
    """Example Acutator which implements actuation by writing
    to a file
    """
    def __init__(self, filename=None):
        self.file = os.path.expanduser(filename)

    def get_state(self, request):
        try:
            with open(self.file, 'r') as fp:
                return self.parse_state(fp.read())
        except IOError:
            return None

    # @authenticated(['__has_ssl__'])
    def set_state(self, request, state):
        with open(self.file, 'w') as fp:
            fp.write(str(state))
        return state

class BinaryActuator(_Actuator, actuate.BinaryActuator):
    def __init__(self, filename=None, range=None):
        _Actuator.__init__(self, filename)
        actuate.BinaryActuator.__init__(self)

class ContinuousActuator(_Actuator, actuate.ContinuousActuator):
    def __init__(self, filename=None, range=None):
        _Actuator.__init__(self, filename)
        actuate.ContinuousActuator.__init__(self, range)

class DiscreteActuator(_Actuator, actuate.NStateActuator):
    def __init__(self, filename=None, states=None):
        _Actuator.__init__(self, filename)
        actuate.NStateActuator.__init__(self, states)


class FileDriver(driver.SmapDriver):
    """Driver which creates a single point backed by a file.  You
    could use this, for instance, to expose flags in /proc"""
    def setup(self, opts):
        # set up an appropriate actuator
        filename = opts.pop('Filename', '~/FileActuatorFile')
        data_type = 'long'
        if not 'model' in opts or opts['model'] == 'binary':
            act = BinaryActuator(filename)
        elif opts['model'] == 'discrete':
            act = DiscreteActuator(filename=filename, states=['cat', 'dog'])
        elif opts['model'] == 'continuous':
            act = ContinuousActuator(filename=filename, range=map(float, opts.pop('range')))
            data_type = 'double'
        else:
            raise ValueError("Invalid actuator model: " + opts['model'])

        self.add_actuator('/point0', 'Switch Position',
                          act, data_type=data_type, write_limit=0)
