"""
This is a collection of virtual devices that seek to provide general interfaces
for devices we might encounter in the real world.
"""
"""
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""
class VirtualLight(object):
    """
    Light that turns on/off
    """
    def __init__(self, startstate=0):
        self.state = startstate

    def on(self):
        self.state = 1
    
    def off(self):
        self.state = 0

    def get_state(self):
        return self.state

class VirtualDimmableLight(object):
    """
    Light that can have its level set 0-100
    """
    def __init__(self, startstate=0):
        self.state = startstate

    def on(self):
        self.state = 100
    
    def off(self):
        self.state = 0

    def set_state(self, state):
        if state >=0 and state <= 100:
            self.state = state

    def get_state(self):
        return self.state

class VirtualSwitch(object):
    """
    Switch that turns on/off
    """
    def __init__(self, startstate=0):
        self.state = startstate

    def on(self):
        self.state = 1
    
    def off(self):
        self.state = 0

    def get_state(self):
        return self.state
    
    def toggle(self):
        self.state = (self.state + 1) % 2

class VirtualDimmerSwitch(object):
    """
    Dimmer switch for setting 0-100
    """
    def __init__(self, startstate=0):
        self.state = startstate

    def on(self):
        self.state = 100
    
    def off(self):
        self.state = 0

    def set_state(self, state):
        if state >=0 and state <= 100:
            self.state = state

    def get_state(self):
        return self.state
