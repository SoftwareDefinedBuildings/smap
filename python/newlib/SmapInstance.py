
import os

import Reporting
import SmapStatus
import SmapContext
import sys

class SmapInstance(dict):
    """
    Class implementing a single smap "instance"; corresponding to a
    root with the normal data/, reporting/, status/, and context/
    resources.  This basically consists of creating a dict with the
    right sub-classes.

    Multiple SmpaInstances can be placed in a hierarchy by a
    SmapServer, or a single one can be the root.

    To use this class, create a dict with the resource structure you
    want to use for your resource class.  The objects at teh leaves of
    the tree should be SmapPoints.  For instance, you could do:

    data = {
        '0' : { 'sensor' : {'0' : SmapPoint.SmapPoint(SmapPoint.Formatting(unit='kW',multiplier=None,
                                                                          divisor=None,type='electric',
                                                                          ctype='sensor'),
                                 SmapPoint.Parameter(interval=1, time='second')) } } }
    inst = SmapInstance.SmapInstance(data, key="mykey")

    This will create the hierarchy /data/0/sensor/0/ with the
    appropriate sMAP resources at the leaves.  The key argument is
    used to name a file for storing reporting instances, and should be
    different for ever sMAP instance run on the same host.

    You can then add data to the instance by using the SmapPoint.add
    method; for instance, you could do

    inst['data']['0']['sensor']['0'].add(SmapPoint.Reading(time=now, value=0, min=None, max=None))

    After you've added all the data, make sure you call push.  This
    lets the service know that you have finished adding data which
    should be sent to any consumers which have registered to receive
    data whenever new readings are available.

    inst.push()

    If you only want to push data in part of the tree, you can call
    push() with a "dirty path": for instance, you could say

    inst.push(dirty_path='~/data/0')

    This will only push data to clients which have asked for a report
    overlapping this path.

    You may set the local timezone during instantiation -- the value
    should be a value from the tz database (zone.tab) file.  On many
    systems, this is available in /usr/share/zoneinfo/zone.tab
    
    """
    def __init__(self, data_hierarchy, key='SmapInstance', timezone='America/Los_Angeles'):
        self.reporting = Reporting.Reporting(self,
                  report_file=os.path.join('/var/smap/', key + '.reports'))
        # map in the user-provided data resource 
        self.__setitem__('data', data_hierarchy)
        self.__setitem__('reporting', Reporting.ReportingHttp(self.reporting))
        self.__setitem__('status', SmapStatus.SmapStatus())
        self.__setitem__('context', SmapContext.SmapContext(timezone))

    def push(self, dirty_path='/'):
        return self.reporting.push(dirty_path)

    def start(self):
        self.reporting.start()

    def is_alive(self):
        return self.reporting.is_alive()
