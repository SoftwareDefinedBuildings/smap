# -*- python -*-

__schema__ = [
    {"description" : "readings",
     "name" : "http://webs.cs.berkeley.edu/schema/meter/data/reading",
     "id" : "readings",
     "type" : "object",
     "properties" : {
       "SummationDelivered" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "false"},
       "SummationReceived" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "true"},
       "SummationInterval" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "true"},
       "PowerFactor" : {"type" : "integer", "minimum" : -100, "maximum" : 100, "optional" : "true"},
       "Max" : {"type" : "integer", "minimum" : 0, "maximum" : 65535, "optional" : "true"},
       "Min" : {"type" : "integer", "minimum" : 0, "maximum" : 65535, "optional" : "true"},
       "Instantaneous" : {"type" : "integer", "minimum" : -32768, "maximum" : 32767, "optional" : "true"},
       "SnapShotTime" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "true"} # POSIX time
       }
     },
    {"name" : "http://webs.cs.berkeley.edu/schema/meter/data/reading_collection",
     "type" : "object",
     "properties" : {
        "MeterName" : {"type" : "string"},
        "Value"     : {"type" : {"$ref" : "http://webs.cs.berkeley.edu/schema/meter/data/reading"}}
       }
     },
    {"name" : "http://webs.cs.berkeley.edu/schema/meter/data/status",
     "id" : "status",
     "type" : "object",
     "properties" : {
       "Status" : {"type" : "integer", "minimum" : 0, "maximum" : 65535, "optional" : "false"}, # 16 bitmap
       "LocalTime" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "true"}
       }
     },
    {"description" : "formatting",
     "name" : "http://webs.cs.berkeley.edu/schema/meter/data/formatting",
     "id" : "formatting",
     "type" : "object",
     "properties" : {
       # "UnitofMeasure" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "false"}, # 8-bit enum
       "UnitofMeasure" : {"type" : "string",
                          "options":[
                             {"value":"kW", "label":"kW/kWh"},
                             {"value":"m3", "label":""},
                             {"value":"ft3"},
                             {"value":"btu"},
                             {"value":"kpa", "label":"kilo-Pascals"},
                             {"value":"lph", "label":"Liters per Hour"},
                             {"value":"gph", "label":"Gallons per Hour"}]},
       "Multiplier" : {"type" : "integer", "minimum" : 0, "maximum" : 65535, "optional" : "true"},
       "Divisor" : {"type" : "integer", "minimum" : 0, "maximum" : 65535, "optional" : "true"},
       # "UnitofTime" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "true"}, # 8-bit enum
       "UnitofTime" : {"type" : "string",
                       "options": [
                          {"value":"microsecond"},
                          {"value":"millisecond"},
                          {"value":"second"},
                          {"value":"minute"},
                          {"value":"hour"},
                          {"value":"day"},
                          {"value":"week"},
                          {"value":"month"},
                          {"value":"year"},
                          {"value":"decade"}]},
       #"MeterType" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "false"} # 8-bit bitmap
        "MeterType" : {"type" : "string",
                       "options": [
                          {"value":"electric"},
                          {"value":"gas"},
                          {"value":"water"},
                          {"value":"thermal"},
                          {"value":"pressure"},
                          {"value":"heat"},
                          {"value":"cooling"}]}
       }
     },
    {"description" : "profile",
     "name" : "http://webs.cs.berkeley.edu/schema/meter/data/profile",
     "id" : "profile",
     "type" : "object",
     "properties" : {
       "EndTime" : {"type" : "integer", "minimum" : 0, "maximum" : 4294967295, "optional" : "false"},
       "Status" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "false"}, # 8 bitmap
       "IntervalPeriod" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "false"}, # 8 enum
       "NumberofPeriod" : {"type" : "integer", "minimum" : 0, "maximum" : 255, "optional" : "false"}, 
       "Intervals" : {"type" : "array",
                      "properties" : {"type" : "integer", "minimum" : -32768, "maximum" : 32767}},
       },
     },
    {"description" : "Install new report",
     "name" : "http://webs.cs.berkeley.edu/schema/meter/reporting/create",
     "id" : "install",
     "type" : "object",
     "properties" : {
       "Period" : {"type" : "integer", "minimum" : 0, "maximum" : 65535}, # in seconds
       "MinPeriod" : {"type" : "integer", "minimum" : 0, "maximum" : 65535},
       "MaxPeriod" : {"type" : "integer", "minimum" : 0, "maximum" : 65535},
       "ReportDeliveryLocation" : {"type" : "string"}, # uri (http://[fec0::25]/receive) (udp://[fec0::25]:8120)
       "ReportResource" : {"type" : "string"}, # local URI of report.  ie /data/reports?fields=foo
       }
     }
    ]


if __name__ == '__main__':
    import BinaryJsonStructs
    print "#ifndef ACME_SCHEMA_H_"
    print "#define ACME_SCHEMA_H_"
    for s in __schema__:
        b = BinaryJsonStructs.BinaryJsonStruct(s)
        print "//",s
        b.generate()
    print "#endif"
