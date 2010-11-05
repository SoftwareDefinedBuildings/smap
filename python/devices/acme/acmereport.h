/*
 * "Copyright (c) 2008, 2009 The Regents of the University  of California.
 * All rights reserved."
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the above copyright notice, the following
 * two paragraphs and the author appear in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
 *
 */

/*
 * Example of creating a packed binaryjson object using the code
 * generation tools.
 *
 * @author <stevedh@eecs.berkeley.edu>
 */

#ifndef _ACMEREPORT_H_
#define _ACMEREPORT_H_

/* BEGIN AUTOMATICALLY GENERATED STRUCTS */
#include <stdint.h>
enum {
  OBJECT_ACMEREPORT_DIGEST = 0x7c0018aaL,
};
typedef enum ACmeReport_keys {
  OBJECT_KEY_avgPower = 0,
  OBJECT_KEY_energy = 1,
  OBJECT_KEY_instPower = 2,
  OBJECT_KEY_maxPower = 3,
  OBJECT_KEY_minPower = 4,
  OBJECT_KEY_period = 5,
} ACmeReport_key_t;


nx_struct object_kv_ACmeReport_avgPower {
  nx_uint8_t key; // = OBJECT_KEY_avgPower
  nx_uint32_t avgPower;
};

nx_struct object_kv_ACmeReport_energy {
  nx_uint8_t key; // = OBJECT_KEY_energy
  nx_uint32_t energy;
};

nx_struct object_kv_ACmeReport_instPower {
  nx_uint8_t key; // = OBJECT_KEY_instPower
  nx_uint32_t instPower;
};

nx_struct object_kv_ACmeReport_maxPower {
  nx_uint8_t key; // = OBJECT_KEY_maxPower
  nx_uint32_t maxPower;
};

nx_struct object_kv_ACmeReport_minPower {
  nx_uint8_t key; // = OBJECT_KEY_minPower
  nx_uint32_t minPower;
};

nx_struct object_kv_ACmeReport_period {
  nx_uint8_t key; // = OBJECT_KEY_period
  nx_uint32_t period;
};

nx_struct object_ACmeReport {
  nx_uint16_t ACmeReport_len;
  nx_uint8_t data[0];
}; 

nx_struct ACmeReport_wrapper {
  nx_uint32_t schemaId; // = 0x7c0018aa
  nx_struct object_ACmeReport object;
};
/* END AUTOMATICALLY GENERATED STRUCTS  */

/* 
 * It's handy to create a single struct using the definitions above so
 * that you can use sizeof() on it, and allocate it easily.
 */
nx_struct ACmeReport {
  nx_struct ACmeReport_wrapper             ar_wrap;
  nx_struct object_kv_ACmeReport_period    ar_period;
  nx_struct object_kv_ACmeReport_minPower  ar_minPower;
  nx_struct object_kv_ACmeReport_maxPower  ar_maxPower;
  nx_struct object_kv_ACmeReport_instPower ar_instPower;
  nx_struct object_kv_ACmeReport_energy    ar_energy;
  nx_struct object_kv_ACmeReport_avgPower  ar_avgPower;
};

int ACmeReport_build(nx_struct ACmeReport *ar,
                     uint32_t period,
                     uint32_t minPower,
                     uint32_t maxPower,
                     uint32_t instPower,
                     uint32_t energy,
                     uint32_t avgPower);
#endif
