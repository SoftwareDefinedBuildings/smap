%module bacnet
%{
#include "bacenum.h"
void Init(char *interface, char *port);
PyObject *whois(unsigned int timeout_seconds);
PyObject *read_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, int32_t array_index);
PyObject *write_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, uint8_t property_tag, PyObject *val_str, uint8_t priority);
const char * type_str(unsigned index);
const char * prop_str(unsigned index);
const char * unit_str(unsigned index);
%}
%include "stdint.i"
%include "bacenum.h"
void Init(char *interface, char *port);
PyObject *whois(unsigned int timeout_seconds);
PyObject *read_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, int32_t array_index = -1);
PyObject *write_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, uint8_t property_tag, PyObject *val_str, uint8_t priority = 16);

const char * type_str(unsigned index);
const char * prop_str(unsigned index);
const char * unit_str(unsigned index);

