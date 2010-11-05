#ifndef ACME_SCHEMA_H_
#define ACME_SCHEMA_H_
// {'id': 'readings', 'properties': {'min': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'SummationDelivered': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}, 'SnapShotTime': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}, 'Instantaneous': {'optional': 'true', 'minimum': -32768, 'type': 'integer', 'maximum': 32767}, 'SummationReceived': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}, 'max': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'PowerFactor': {'optional': 'true', 'minimum': -100, 'type': 'integer', 'maximum': 100}, 'SummationInterval': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}}, 'type': 'object', 'description': 'readings', 'name': 'http://webs.cs.berkeley.edu/schema/meter/data/readings'}
enum {
  OBJECT_READINGS_DIGEST = 0x88003759L,
};
typedef enum readings_keys {
  OBJECT_KEY_Instantaneous = 0,
  OBJECT_KEY_PowerFactor = 1,
  OBJECT_KEY_SnapShotTime = 2,
  OBJECT_KEY_SummationDelivered = 3,
  OBJECT_KEY_SummationInterval = 4,
  OBJECT_KEY_SummationReceived = 5,
  OBJECT_KEY_max = 6,
  OBJECT_KEY_min = 7,
} readings_key_t;


nx_struct object_kv_readings_Instantaneous {
  nx_uint8_t key; // = OBJECT_KEY_Instantaneous
  nx_int32_t Instantaneous;
};

nx_struct object_kv_readings_PowerFactor {
  nx_uint8_t key; // = OBJECT_KEY_PowerFactor
  nx_int8_t PowerFactor;
};

nx_struct object_kv_readings_SnapShotTime {
  nx_uint8_t key; // = OBJECT_KEY_SnapShotTime
  nx_uint32_t SnapShotTime;
};

nx_struct object_kv_readings_SummationDelivered {
  nx_uint8_t key; // = OBJECT_KEY_SummationDelivered
  nx_uint32_t SummationDelivered;
};

nx_struct object_kv_readings_SummationInterval {
  nx_uint8_t key; // = OBJECT_KEY_SummationInterval
  nx_uint32_t SummationInterval;
};

nx_struct object_kv_readings_SummationReceived {
  nx_uint8_t key; // = OBJECT_KEY_SummationReceived
  nx_uint32_t SummationReceived;
};

nx_struct object_kv_readings_max {
  nx_uint8_t key; // = OBJECT_KEY_max
  nx_uint16_t max;
};

nx_struct object_kv_readings_min {
  nx_uint8_t key; // = OBJECT_KEY_min
  nx_uint16_t min;
};

nx_struct object_readings {
  nx_uint16_t readings_len;
  nx_uint8_t data[0];
}; 

nx_struct readings_wrapper {
  nx_uint32_t schemaId; // = 0x88003759
  nx_struct object_readings object;
};
// {'properties': {'Status': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'LocalTime': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}}, 'type': 'object', 'name': 'http://webs.cs.berkeley.edu/schema/meter/data/status', 'id': 'status'}
enum {
  OBJECT_STATUS_DIGEST = 0xfd004af9L,
};
typedef enum status_keys {
  OBJECT_KEY_LocalTime = 0,
  OBJECT_KEY_Status = 1,
} status_key_t;


nx_struct object_kv_status_LocalTime {
  nx_uint8_t key; // = OBJECT_KEY_LocalTime
  nx_uint32_t LocalTime;
};

nx_struct object_kv_status_Status {
  nx_uint8_t key; // = OBJECT_KEY_Status
  nx_uint16_t Status;
};

nx_struct object_status {
  nx_uint16_t status_len;
  nx_uint8_t data[0];
}; 

nx_struct status_wrapper {
  nx_uint32_t schemaId; // = 0xfd004af9
  nx_struct object_status object;
};
// {'id': 'formatting', 'properties': {'UnitofTime': {'type': 'string', 'options': [{'value': 'microsecond'}, {'value': 'millisecond'}, {'value': 'second'}, {'value': 'minute'}, {'value': 'hour'}, {'value': 'day'}, {'value': 'week'}, {'value': 'month'}, {'value': 'year'}, {'value': 'decade'}]}, 'UnitofMeasure': {'type': 'string', 'options': [{'value': 'kW', 'label': 'kW/kWh'}, {'value': 'm3', 'label': ''}, {'value': 'ft3'}, {'value': 'btu'}, {'value': 'kpa', 'label': 'kilo-Pascals'}, {'value': 'lph', 'label': 'Liters per Hour'}, {'value': 'gph', 'label': 'Gallons per Hour'}]}, 'MeterType': {'type': 'string', 'options': [{'value': 'electric'}, {'value': 'gas'}, {'value': 'water'}, {'value': 'thermal'}, {'value': 'pressure'}, {'value': 'heat'}, {'value': 'cooling'}]}, 'Divisor': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'Multiplier': {'optional': 'true', 'minimum': 0, 'type': 'integer', 'maximum': 65535}}, 'type': 'object', 'description': 'formatting', 'name': 'http://webs.cs.berkeley.edu/schema/meter/data/formatting'}
enum {
  OBJECT_FORMATTING_DIGEST = 0xb000a4aeL,
};
typedef enum formatting_keys {
  OBJECT_KEY_Divisor = 0,
  OBJECT_KEY_MeterType = 1,
  OBJECT_KEY_Multiplier = 2,
  OBJECT_KEY_UnitofMeasure = 3,
  OBJECT_KEY_UnitofTime = 4,
} formatting_key_t;


nx_struct object_kv_formatting_Divisor {
  nx_uint8_t key; // = OBJECT_KEY_Divisor
  nx_uint16_t Divisor;
};
enum {
  STRING_VAL_ELECTRIC = 0,
  STRING_VAL_GAS = 1,
  STRING_VAL_WATER = 2,
  STRING_VAL_THERMAL = 3,
  STRING_VAL_PRESSURE = 4,
  STRING_VAL_HEAT = 5,
  STRING_VAL_COOLING = 6,
};

nx_struct object_kv_formatting_MeterType {
  nx_uint8_t key; // = OBJECT_KEY_MeterType
  nx_uint8_t MeterType;
};

nx_struct object_kv_formatting_Multiplier {
  nx_uint8_t key; // = OBJECT_KEY_Multiplier
  nx_uint16_t Multiplier;
};
enum {
  STRING_VAL_KW = 0,
  STRING_VAL_M3 = 1,
  STRING_VAL_FT3 = 2,
  STRING_VAL_BTU = 3,
  STRING_VAL_KPA = 4,
  STRING_VAL_LPH = 5,
  STRING_VAL_GPH = 6,
};

nx_struct object_kv_formatting_UnitofMeasure {
  nx_uint8_t key; // = OBJECT_KEY_UnitofMeasure
  nx_uint8_t UnitofMeasure;
};
enum {
  STRING_VAL_MICROSECOND = 0,
  STRING_VAL_MILLISECOND = 1,
  STRING_VAL_SECOND = 2,
  STRING_VAL_MINUTE = 3,
  STRING_VAL_HOUR = 4,
  STRING_VAL_DAY = 5,
  STRING_VAL_WEEK = 6,
  STRING_VAL_MONTH = 7,
  STRING_VAL_YEAR = 8,
  STRING_VAL_DECADE = 9,
};

nx_struct object_kv_formatting_UnitofTime {
  nx_uint8_t key; // = OBJECT_KEY_UnitofTime
  nx_uint8_t UnitofTime;
};

nx_struct object_formatting {
  nx_uint16_t formatting_len;
  nx_uint8_t data[0];
}; 

nx_struct formatting_wrapper {
  nx_uint32_t schemaId; // = 0xb000a4ae
  nx_struct object_formatting object;
};
// {'id': 'profile', 'properties': {'Status': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 255}, 'NumberofPeriod': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 255}, 'EndTime': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 4294967295}, 'IntervalPeriod': {'optional': 'false', 'minimum': 0, 'type': 'integer', 'maximum': 255}, 'Intervals': {'type': 'array', 'properties': {'minimum': -32768, 'type': 'integer', 'maximum': 32767}}}, 'type': 'object', 'description': 'profile', 'name': 'http://webs.cs.berkeley.edu/schema/meter/data/profile'}
enum {
  OBJECT_PROFILE_DIGEST = 0xd500c6eaL,
};
typedef enum profile_keys {
  OBJECT_KEY_EndTime = 0,
  OBJECT_KEY_IntervalPeriod = 1,
  OBJECT_KEY_Intervals = 2,
  OBJECT_KEY_NumberofPeriod = 3,
  OBJECT_KEY_Status = 4,
} profile_key_t;


nx_struct object_kv_profile_EndTime {
  nx_uint8_t key; // = OBJECT_KEY_EndTime
  nx_uint32_t EndTime;
};

nx_struct object_kv_profile_IntervalPeriod {
  nx_uint8_t key; // = OBJECT_KEY_IntervalPeriod
  nx_uint8_t IntervalPeriod;
};

nx_struct array_Intervals {
  nx_uint16_t Intervals_len; // the length of the array data in octets
  nx_int32_t Intervals_elt[0];
};

nx_struct object_kv_profile_Intervals {
  nx_uint8_t key; // = OBJECT_KEY_Intervals
  nx_struct array_Intervals Intervals_1;
};

nx_struct object_kv_profile_NumberofPeriod {
  nx_uint8_t key; // = OBJECT_KEY_NumberofPeriod
  nx_uint8_t NumberofPeriod;
};

nx_struct object_kv_profile_Status {
  nx_uint8_t key; // = OBJECT_KEY_Status
  nx_uint8_t Status;
};

nx_struct object_profile {
  nx_uint16_t profile_len;
  nx_uint8_t data[0];
}; 

nx_struct profile_wrapper {
  nx_uint32_t schemaId; // = 0xd500c6ea
  nx_struct object_profile object;
};
// {'id': 'install', 'properties': {'ReportType': {'type': 'string'}, 'MaxPeriod': {'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'Addr': {'type': 'string'}, 'MinPeriod': {'minimum': 0, 'type': 'integer', 'maximum': 65535}, 'Period': {'minimum': 0, 'type': 'integer', 'maximum': 65535}}, 'type': 'object', 'description': 'Install new report', 'name': 'http://webs.cs.berkeley.edu/schema/meter/reporting/create'}
enum {
  OBJECT_INSTALL_DIGEST = 0xb30036b2L,
};
typedef enum install_keys {
  OBJECT_KEY_Addr = 0,
  OBJECT_KEY_MaxPeriod = 1,
  OBJECT_KEY_MinPeriod = 2,
  OBJECT_KEY_Period = 3,
  OBJECT_KEY_ReportType = 4,
} install_key_t;


nx_struct string_Addr {
  nx_uint16_t Addr_len; // the length of the string data in octets
  nx_uint8_t  Addr[0];
};

nx_struct object_kv_install_Addr {
  nx_uint8_t key; // = OBJECT_KEY_Addr
  nx_struct string_Addr Addr_1;
};

nx_struct object_kv_install_MaxPeriod {
  nx_uint8_t key; // = OBJECT_KEY_MaxPeriod
  nx_uint16_t MaxPeriod;
};

nx_struct object_kv_install_MinPeriod {
  nx_uint8_t key; // = OBJECT_KEY_MinPeriod
  nx_uint16_t MinPeriod;
};

nx_struct object_kv_install_Period {
  nx_uint8_t key; // = OBJECT_KEY_Period
  nx_uint16_t Period;
};

nx_struct string_ReportType {
  nx_uint16_t ReportType_len; // the length of the string data in octets
  nx_uint8_t  ReportType[0];
};

nx_struct object_kv_install_ReportType {
  nx_uint8_t key; // = OBJECT_KEY_ReportType
  nx_struct string_ReportType ReportType_2;
};

nx_struct object_install {
  nx_uint16_t install_len;
  nx_uint8_t data[0];
}; 

nx_struct install_wrapper {
  nx_uint32_t schemaId; // = 0xb30036b2
  nx_struct object_install object;
};
#endif
