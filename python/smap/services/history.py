"""
@author Gabe Fierro <gt.fierro@berkeley.edu>
"""
import json
import os
import glob
import shutil
import re

"""
Handles histories of devices and their configurations as created by the discovery service.

For each device, we track:
* MAC address
* IP address
* location of generated ini file
* last time scanned
* sMAP driver port

The historian should be able to start/restart and pick up on the status of the discovery
service as it was last run by looking at the most recent config file. A new version of the
config file will be created every time a scan is run.

The naming scheme for log files will follow the pattern of the most recent file being 'configfile.json',
the next most recent being 'configfile.json.1', then 'configfile.json.2' etc.
"""

class Historian(object):
    def __init__(self, directory, basename):
        """
        basename is a string that is the root name of the config file, that is, for a configuration
        file named 'history.json', the basename is 'history'.
        """
        self.directory = directory
        self.basename = basename
        self.config = {}
        configpath = os.path.join(self.directory, self.basename+'.json')
        if os.path.exists(configpath):
            self.config = json.load(open(configpath))

    def _increment_filename(self, filename):
        """
        filename is a string.
        If [filename] ends in a number 'n' (e.g. basename.json.n), then this function returns the string
        'basename.json.n+1'.
        If [filename] doesn't end in a number, then it returns 'basename.json.1'
        """
        match = re.search('(.*{0}.json).?([0-9]+)?'.format(self.basename), filename)
        if not match:
            print 'something is probably super wrong'
        name, number = match.groups()
        new_number = int(number) + 1 if number is not None else 1
        return name+'.'+str(new_number)

    def _rotate(self):
        """
        We call _rotate before we save a new file. Because the most recent file is always basename.json,
        before we save that file, we need to increment the numbers on all the preexisting files
        """
        # iterate through all the ones with numbers
        # start from the highest number and work our way down to 1
        for filename in sorted(glob.iglob(os.path.join(self.directory,'{0}.json.*'.format(self.basename))), key=lambda x: int(x.split('.')[-1]), reverse=True):
            shutil.move(filename, self._increment_filename(filename))
        # add .1 to the current basename.json
        current = os.path.join(self.directory,'{0}.json'.format(self.basename))
        if os.path.exists(current):
            shutil.move(current, self._increment_filename(current))

    def new_config(self, config):
        """
        Given a new dictionary of configuration, we want to save it into basename.json
        """
        self._rotate()
        json.dump(config, open(os.path.join(self.directory,self.basename+'.json'),'w+'))
        self.config = config

    def save(self):
        """
        Save our own configuration in a new versioned file
        """
        self.new_config(self.config)
