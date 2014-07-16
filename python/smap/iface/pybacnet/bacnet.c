/* -*- c-basic-offset: 4 -*- */
/* vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 */
/**************************************************************************
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* Based on BACnet stack: Copyright 2006 Steve Karg <skarg@users.sourceforge.net>
* Copyright 2010 Andrew Krioukov <krioukov@cs.berkeley.edu>
* Bugs and GIL fixes, Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>

* Python interface to BACnet using BACnet stack library
*********************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <Python.h>
#include <assert.h>
#include <pthread.h>

#define PRINT_ENABLED 1

#include "bactext.h"
#include "iam.h"
#include "address.h"
#include "config.h"
#include "bacdef.h"
#include "npdu.h"
#include "apdu.h"
#include "device.h"
#include "datalink.h"
#include "tsm.h"
#include "filename.h"
#include "handlers.h"
#include "client.h"
#include "txbuf.h"
#include "dlenv.h"
#include "awf.h"
#include "arf.h"

int PyDict_SetItemString_Steal(PyObject *p, const char *key, PyObject *val) {
  int r = PyDict_SetItemString(p, key, val);
  assert(val->ob_refcnt > 1);
  Py_DECREF(val);
  return r;
}

int PyList_Append_Steal(PyObject *list, PyObject *item) {
  int r = PyList_Append(list, item);
  assert(val->ob_refcnt > 1);
  Py_DECREF(item);
  return r;
}

/* All included BACnet objects */
static object_functions_t Object_Table[] = {
    {DEVICE_OBJ_FUNCTIONS},
    {MAX_BACNET_OBJECT_TYPE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL},
};

/* buffer used for receive */
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

/* global variables used in this file */
static bool Error_Detected = false;
static PyObject *read_result = NULL;
static char write_ack = 0;
static struct {
    BACNET_ADDRESS *dest;
    uint8_t invoke_id;
} outstanding;
static pthread_mutex_t busy = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
    READ_PROPERTY,
    WRITE_PROPERTY,
    ATOMIC_WRITE_FILE,
    ATOMIC_READ_FILE,
} command_type_t;

void MyErrorHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    BACNET_ERROR_CLASS error_class,
    BACNET_ERROR_CODE error_code) {
    if (outstanding.dest &&
        invoke_id != outstanding.invoke_id &&
        address_match(src, outstanding.dest)) return;
    Error_Detected = true;
    PyErr_Format(PyExc_IOError, "BACnet Error: %s: %s",
                 bactext_error_class_name((int) error_class),
                 bactext_error_code_name((int) error_code));
}


void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server) {
    (void) server;

    if (outstanding.dest &&
        invoke_id != outstanding.invoke_id &&
        address_match(src, outstanding.dest)) return;
    Error_Detected = true;
    PyErr_Format(PyExc_IOError, "BACnet abort: %s",
                 bactext_abort_reason_name(abort_reason));
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason) {
    if (outstanding.dest &&
        invoke_id != outstanding.invoke_id &&
        address_match(src, outstanding.dest)) return;
    Error_Detected = true;
    PyErr_Format(PyExc_IOError, "BACnet reject: %s",
                 bactext_reject_reason_name(reject_reason));
}

/** decode_data - decodes bacnet properties to python objects
  * based on bacapp.c:bacapp_print_value()
  */

static PyObject *decode_data(BACNET_READ_PROPERTY_DATA * data) {               
    BACNET_APPLICATION_DATA_VALUE value;
    int len = 0;
    uint8_t *application_data;
    int application_data_len;

    PyObject *ret = PyList_New(0);

    if (data) {
        application_data = data->application_data;
        application_data_len = data->application_data_len;
        while (application_data_len > 0) {
            len =
                bacapp_decode_application_data(application_data,
                (uint8_t) application_data_len, &value);
            if (len == 0) break;

            switch (value.tag) {
              case BACNET_APPLICATION_TAG_OBJECT_ID:
              {
                PyObject *rec = PyDict_New();
                PyDict_SetItemString_Steal(rec, "type", Py_BuildValue("i",value.type.Object_Id.type));
                if (value.type.Object_Id.type < MAX_ASHRAE_OBJECT_TYPE) {
                  PyDict_SetItemString_Steal(rec, "type_str", 
                    Py_BuildValue("s",bactext_object_type_name(value.type.Object_Id.type)));
                }
                PyDict_SetItemString_Steal(rec, "instance", Py_BuildValue("i",value.type.Object_Id.instance));
                PyList_Append_Steal(ret, rec);
                break;
              }
              case BACNET_APPLICATION_TAG_CHARACTER_STRING:
                PyList_Append_Steal(ret, Py_BuildValue("s", value.type.Character_String.value));
                break;
              case BACNET_APPLICATION_TAG_NULL:
                PyList_Append(ret, Py_None);
                break;
              case BACNET_APPLICATION_TAG_BOOLEAN:
                PyList_Append_Steal(ret, Py_BuildValue("i", (int)value.type.Boolean));
                break;
              case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                PyList_Append_Steal(ret, Py_BuildValue("I", (int)value.type.Unsigned_Int));
                break;
              case BACNET_APPLICATION_TAG_SIGNED_INT:
                PyList_Append_Steal(ret, Py_BuildValue("i", (int)value.type.Signed_Int));
                break;
              case BACNET_APPLICATION_TAG_REAL:
                PyList_Append_Steal(ret, Py_BuildValue("d", (double)value.type.Real));
                break;
              case BACNET_APPLICATION_TAG_DOUBLE:
                PyList_Append_Steal(ret, Py_BuildValue("d", (double)value.type.Double));
                break;
              case BACNET_APPLICATION_TAG_ENUMERATED:
                PyList_Append_Steal(ret, Py_BuildValue("i", (int)value.type.Enumerated));
                break;
              default:
                fprintf(stderr,"Unknown tag %d\n", value.tag);
            }
            application_data += len;  //Increment ptr
            application_data_len -= len;
        }   
    }
    if (PyList_Size(ret) == 1) {
        PyObject *new_ret = PyList_GetItem(ret, 0);
        Py_INCREF(new_ret);
        Py_DECREF(ret);
        return new_ret;
    } else {
        return ret;
    }
}

/** Handler for a ReadProperty ACK. */
void My_Read_Property_Ack_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA * service_data) {
    int len = 0;
    BACNET_READ_PROPERTY_DATA data;

    len = rp_ack_decode_service_request(service_request, service_len, &data);
    // fprintf(stderr, "receive: %i %i\n", service_data->invoke_id, outstanding.invoke_id);
    if (len > 0 &&
        outstanding.dest &&
        address_match(src, outstanding.dest)) {
            read_result = decode_data(&data);
        }
}

/** Handler for AtomicWriteFile ACK  */
void My_Atomic_Write_File_Ack_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA * service_data) {
    int len = 0;
    BACNET_ATOMIC_WRITE_FILE_DATA data;

    len = awf_ack_decode_service_request(service_request, service_len, &data);
    if (len > 0 &&
	outstanding.dest &&
	address_match(src, outstanding.dest)) {
	read_result = PyString_FromStringAndSize(data.fileData.value,
						 data.fileData.length);
    }
}

/** Handler for AtomicWriteFile ACK  */
void My_Atomic_Read_File_Ack_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA * service_data) {
    int len = 0;
    BACNET_ATOMIC_READ_FILE_DATA data;

    len = arf_ack_decode_service_request(service_request, service_len, &data);
    if (len > 0 &&
	outstanding.dest &&
	address_match(src, outstanding.dest)) {
	read_result = PyString_FromStringAndSize(data.fileData.value,
						 data.fileData.length);
    }
}

/** Handler for WriteProperty ACK. */
void MyWritePropertySimpleAckHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id)
{
    write_ack = 1;
    //printf("\r\nWriteProperty Acknowledged!\r\n");
}

/**
  * Init() - Initialize bacnet lib
  * Opens socket to listen for replies, defines handlers
  * for various message types/
*/
void Init(char *interface, char *port) {
#ifndef _WIN32
    if (interface != NULL)
      setenv("BACNET_IFACE", interface, 1);
    if (port != NULL) {
      //fprintf(stderr, "Warning: Chaning the port does not work for whois.\n");
      setenv("BACNET_IP_PORT", port, 1);
    }
#endif

    //Device_Set_Object_Instance_Number(BACNET_MAX_INSTANCE);
    Device_Init(&Object_Table[0]);

    /* we need to handle who-is to support dynamic device binding to us
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    */

    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_add);

    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler
        (handler_unrecognized_service);

    /* we must implement read property - it's required!
    apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        handler_read_property);
    */
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_READ_PROPERTY,
        My_Read_Property_Ack_Handler);
    apdu_set_confirmed_simple_ack_handler(SERVICE_CONFIRMED_WRITE_PROPERTY,
        MyWritePropertySimpleAckHandler);
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_ATOMIC_WRITE_FILE,
        My_Atomic_Write_File_Ack_Handler);
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_ATOMIC_READ_FILE,
        My_Atomic_Read_File_Ack_Handler);

    /* handle errors */
    apdu_set_error_handler(SERVICE_CONFIRMED_WRITE_PROPERTY, MyErrorHandler);
    apdu_set_error_handler(SERVICE_CONFIRMED_READ_PROPERTY, MyErrorHandler);
    apdu_set_error_handler(SERVICE_CONFIRMED_ATOMIC_READ_FILE, MyErrorHandler);
    apdu_set_error_handler(SERVICE_CONFIRMED_ATOMIC_WRITE_FILE, MyErrorHandler);

    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);
    
    address_init();
    dlenv_init();
}

static PyObject *list_from_array(uint8_t *array, unsigned int len) {
  int i;
  PyObject *ret = PyList_New(len);
  for (i = 0; i < len; i++) {
    PyList_SetItem(ret, i, Py_BuildValue("B", array[i]));
  }
  if (!ret)
    Py_RETURN_NONE;
  return ret;
}

static int array_from_list(PyObject *list, uint8_t *array, unsigned int maxlen) {
  int i, len;

  if(!PyList_Check(list)) return -1;
  len = PyList_Size(list);
  if(len > maxlen) return -1;

  for (i = 0; i < len; i++) {
    PyObject *item = PyList_GetItem(list, i);
    if (!item || !PyInt_Check(item)) {
      return -1;
    }
    array[i] = (uint8_t) PyInt_AsLong(item);
  }
  return 1;
}


PyObject *whois(unsigned int timeout_seconds) {
    int i; 
    BACNET_ADDRESS address;
    uint32_t device_id = 0;
    unsigned max_apdu = 0;

    BACNET_ADDRESS src = { 0 };
    uint16_t pdu_len = 0;
    time_t current_seconds = 0;
    time_t last_seconds = time(NULL);
    time_t total_seconds = 0;
    PyObject * ret = NULL;

    Error_Detected = false;
    Send_WhoIs(-1, -1);
    outstanding.invoke_id = 0;
    outstanding.dest = NULL;

    Py_BEGIN_ALLOW_THREADS;
    pthread_mutex_lock(&busy);
    Py_END_ALLOW_THREADS;

    while(true) {
        /* increment timer - exit if timed out */
        current_seconds = time(NULL);
        
        /* returns 0 bytes on timeout */
        Py_BEGIN_ALLOW_THREADS;
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, 100);
        Py_END_ALLOW_THREADS;
        if (pdu_len) {
            npdu_handler(&src, &Rx_Buf[0], pdu_len);
        }
        if (Error_Detected) {
            break;
        }

        /* increment timer - exit if timed out */
        total_seconds += current_seconds - last_seconds;
        last_seconds = current_seconds;
        if (total_seconds > timeout_seconds) {
            break;
        }
    }
    pthread_mutex_unlock(&busy);

    /* Pull the servers we got */ 
    ret = PyList_New(0);
    if (!ret)  {
        PyErr_SetNone(PyExc_MemoryError);
        return NULL;
    }
    for (i = 0; i < MAX_ADDRESS_CACHE; i++) {
        if (address_get_by_index(i, &device_id, &max_apdu, &address)) {
            PyObject *rec = PyDict_New();
            PyDict_SetItemString_Steal(rec, "device_id", Py_BuildValue("I",device_id));
            PyDict_SetItemString_Steal(rec, "max_apdu", Py_BuildValue("I",max_apdu));
            PyDict_SetItemString_Steal(rec, "mac", list_from_array(address.mac, address.mac_len));
            PyDict_SetItemString_Steal(rec, "net", Py_BuildValue("I",address.net));
            PyDict_SetItemString_Steal(rec, "adr", list_from_array(address.adr, address.len));

            PyList_Append_Steal(ret, rec);
        }
    }

    return ret;
}

static int parse_dev(PyObject *dev, uint32_t *device_id, unsigned *max_apdu, BACNET_ADDRESS *dest) {
    PyObject *tmp;
    if (!PyDict_Check(dev)) {
        return 0;
    }

    *device_id = (uint32_t) PyInt_AsLong(PyDict_GetItemString(dev, "device_id"));
    *max_apdu = (unsigned) PyInt_AsLong(PyDict_GetItemString(dev, "max_apdu"));
    dest->net = (uint16_t) PyInt_AsLong(PyDict_GetItemString(dev, "net"));
    
    tmp = PyDict_GetItemString(dev, "mac");
    dest->mac_len = PyList_Size(tmp);
    array_from_list(tmp, dest->mac, MAX_MAC_LEN);

    tmp = PyDict_GetItemString(dev, "adr");
    dest->len = PyList_Size(tmp);
    array_from_list(tmp, dest->adr, MAX_MAC_LEN);

    return 1;
}

static uint8_t send_req(command_type_t type, BACNET_ADDRESS *dest, unsigned max_apdu, void *data) {
    uint8_t invoke_id = 0;
    BACNET_ADDRESS my_address;
    int len = 0;
    int pdu_len = 0;
    int bytes_sent = 0;
    BACNET_NPDU_DATA npdu_data;

    invoke_id = tsm_next_free_invokeID();
    if (!invoke_id) {
        PyErr_SetString(PyExc_IOError, "No available invoke id");
        return 0;
    }

    datalink_get_my_address(&my_address);
    npdu_encode_npdu_data(&npdu_data, true, MESSAGE_PRIORITY_NORMAL);
    pdu_len =
        npdu_encode_pdu(&Handler_Transmit_Buffer[0], dest, &my_address,
        &npdu_data);

    if (type == READ_PROPERTY) {
        len = rp_encode_apdu(&Handler_Transmit_Buffer[pdu_len], 
                             invoke_id, 
                             (BACNET_READ_PROPERTY_DATA *)data);
    } else if (type == WRITE_PROPERTY) {
        len = wp_encode_apdu(&Handler_Transmit_Buffer[pdu_len], 
                             invoke_id, 
                             (BACNET_WRITE_PROPERTY_DATA *)data);
    } else if (type == ATOMIC_WRITE_FILE) {
        len = awf_encode_apdu(&Handler_Transmit_Buffer[pdu_len],
                              invoke_id,
                              (BACNET_ATOMIC_WRITE_FILE_DATA *)data);
    } else if (type == ATOMIC_READ_FILE) {
        len = arf_encode_apdu(&Handler_Transmit_Buffer[pdu_len],
                              invoke_id,
                              (BACNET_ATOMIC_WRITE_FILE_DATA *)data);
    } else {
	PyErr_SetString(PyExc_ValueError, "send_req: invalid request type");
        return 0;
    }

    pdu_len += len;
    if ((unsigned) pdu_len < max_apdu) {
        tsm_set_confirmed_unsegmented_transaction(invoke_id, dest,
            &npdu_data, &Handler_Transmit_Buffer[0], (uint16_t) pdu_len);
        bytes_sent =
            datalink_send_pdu(dest, &npdu_data,
                              &Handler_Transmit_Buffer[0], pdu_len);
        if (bytes_sent <= 0) {
            tsm_free_invoke_id(invoke_id);
            PyErr_Format(PyExc_IOError, "Failed to Send Request (%s)!",
                         strerror(errno));
            return 0;
        }
    } else {
        tsm_free_invoke_id(invoke_id);
        PyErr_Format(PyExc_IOError, "Failed to Send Request "
                     "(exceeds destination maximum APDU)!\n");
        return 0;
    }
    return invoke_id;
}

static int wait_reply(uint8_t invoke_id) {
    BACNET_ADDRESS src = { 0 };
    BACNET_ADDRESS tmp = { 0 };
    int pdu_len = 0;
    uint8_t got_data = 0;
    time_t last_seconds = time(NULL);;
    time_t current_seconds = 0;
    time_t elapsed_seconds = 0;
    time_t timeout_seconds = (apdu_timeout() / 1000) * apdu_retries();

    Error_Detected = false;
    last_seconds = time(NULL);

    PyErr_Clear();              /* shouldn't be here if there's been an exception... */
    while (true) {
        current_seconds = time(NULL);
        if (current_seconds != last_seconds) {
          tsm_timer_milliseconds(((current_seconds - last_seconds) * 1000));
        }
        if (Error_Detected) {
            break;
          }

        if (tsm_invoke_id_free(invoke_id)) {
            break;
        } else if (tsm_invoke_id_failed(invoke_id)) {
            //fprintf(stderr, "Error: TSM Timeout!\n");
            Error_Detected = true;
            break;
        }

        /* returns 0 bytes on 100ms timeout */
        Py_BEGIN_ALLOW_THREADS;
        pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, 100);
        Py_END_ALLOW_THREADS;

        got_data = got_data | Rx_Buf[0];
        tmp = src;
        if (pdu_len) {
            /*
             * here we use &tmp because in bacnet-stack-0.6.0, the len field in the BACNET_ADDRESS
             * struct gets set to 0 in the case of an NPDU error
             */
            npdu_handler(&tmp, &Rx_Buf[0], pdu_len);
        } 

        elapsed_seconds += (current_seconds - last_seconds);
        last_seconds = current_seconds;
        // fprintf(stderr, "Elapsed: %i timeout: %i\n", elapsed_seconds, timeout_seconds);
        if (elapsed_seconds > timeout_seconds) {
            PyErr_Format(PyExc_IOError, "Timeout waiting for reply");
            return 0;
        }
    }

    if (got_data && !Error_Detected) {
        return 1;
    } else {
        return 0;
    }
}

PyObject *read_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, int32_t array_index)
{
    uint32_t device_id;
    unsigned max_apdu = 0;
    BACNET_ADDRESS dest;
    uint8_t invoke_id = 0;
    BACNET_READ_PROPERTY_DATA data;

    // printf("tsm: %i invoke_ids available\n", tsm_transaction_idle_count());

    if (object_type > MAX_BACNET_OBJECT_TYPE ||
        object_instance > BACNET_MAX_INSTANCE ||
        object_property > MAX_BACNET_PROPERTY_ID) {
        Py_RETURN_NONE;
    }
   
    /* Unpack device object */ 
    if (!parse_dev(dev, &device_id, &max_apdu, &dest)) {
        PyErr_SetNone(PyExc_ValueError);
        return NULL;
    }

    data.object_type = object_type;
    data.object_instance = object_instance;
    data.object_property = object_property;
    if (array_index < 0)
      data.array_index = BACNET_ARRAY_ALL;
    else
      data.array_index = array_index;

    /* Send Read Prop */
    Py_BEGIN_ALLOW_THREADS;
    pthread_mutex_lock(&busy);
    Py_END_ALLOW_THREADS;

    if ((invoke_id = send_req(READ_PROPERTY, &dest, max_apdu, &data)) == 0) {
        pthread_mutex_unlock(&busy);
        return NULL;
    }

    /* Recieve Reply */
    outstanding.invoke_id = invoke_id;
    outstanding.dest = &dest;
    read_result = NULL;
    if (wait_reply(invoke_id) && read_result != NULL) {
        tsm_free_invoke_id(invoke_id);
        pthread_mutex_unlock(&busy);
        return read_result;
    } else {
        tsm_free_invoke_id(invoke_id);
        pthread_mutex_unlock(&busy);
        return NULL;    /* SDH : wait_reply sets the exception code */
    }
}



PyObject *write_prop(PyObject *dev, uint32_t object_type, uint32_t object_instance, uint32_t object_property, uint8_t property_tag, PyObject *val_str, uint8_t priority)
{
    // TODO: we do not currently support tuples of (tag, value)

    uint32_t device_id;
    unsigned max_apdu = 0;
    BACNET_ADDRESS dest;
    uint8_t invoke_id = 0;
    BACNET_WRITE_PROPERTY_DATA data;
    int status;
    char *value = PyString_AsString(val_str);
 
    BACNET_APPLICATION_DATA_VALUE object_value;
    uint8_t application_data[MAX_APDU];
    int application_data_len = 0;
    // Specify default index
    int32_t array_index = BACNET_ARRAY_ALL;

    // printf("tsm: %i invoke_ids available\n", tsm_transaction_idle_count());

    if (object_type > MAX_BACNET_OBJECT_TYPE ||
        object_instance > BACNET_MAX_INSTANCE ||
        object_property > MAX_BACNET_PROPERTY_ID ||
        property_tag >= MAX_BACNET_APPLICATION_TAG) {
        PyErr_Format(PyExc_ValueError, "Invalid type, instance, or property");
        return NULL;
    }

    /* Unpack device object */ 
    if (!parse_dev(dev, &device_id, &max_apdu, &dest)) {
        PyErr_Format(PyExc_ValueError, "Could not parse device information!");
        return NULL;
    }

    memset(application_data, 0, sizeof(application_data));
    memset(&object_value, 0, sizeof(object_value));
    memset(&data, 0, sizeof(data));
    status = bacapp_parse_application_data(property_tag, value, &object_value);
    if (!status) {
        fprintf(stderr, "Could not parse value: %s\n", value);
        PyErr_Format(PyExc_ValueError, "Could not parse value: %s", value);
        return NULL;
    }
    application_data_len = bacapp_encode_data(application_data, &object_value);

    data.object_type = object_type;
    data.object_instance = object_instance;
    data.object_property = object_property;
    data.array_index = array_index;
    data.application_data_len = application_data_len;
    assert(sizeof(data.application_data) > application_data_len);
    memcpy(data.application_data, application_data, application_data_len);
    data.priority = priority;

    Py_BEGIN_ALLOW_THREADS;
    pthread_mutex_lock(&busy);
    Py_END_ALLOW_THREADS;

    /* Send Write Prop */
    if ((invoke_id = send_req(WRITE_PROPERTY, &dest, max_apdu, &data)) == 0) {
        pthread_mutex_unlock(&busy);
        return NULL;
    }

    /* Recieve Reply */
    outstanding.invoke_id = invoke_id;
    outstanding.dest = &dest;
    write_ack = 0;
    if (wait_reply(invoke_id)) {
        tsm_free_invoke_id(invoke_id);
        pthread_mutex_unlock(&busy);
        return Py_BuildValue("b", write_ack);
    } else {
        tsm_free_invoke_id(invoke_id);
        pthread_mutex_unlock(&busy);
        return NULL;
    }
}

const char * type_str(unsigned index)
{
  return bactext_object_type_name(index);
}

const char * prop_str(unsigned index)
{
  return bactext_property_name(index);
}

const char * unit_str(unsigned index)
{
  return bactext_engineering_unit_name(index);
}

