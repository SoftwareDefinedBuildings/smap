
#include <stdio.h>

#include "acmereport.h"

int ACmeReport_build(nx_struct ACmeReport *ar,
                     uint32_t period,
                     uint32_t minPower,
                     uint32_t maxPower,
                     uint32_t instPower,
                     uint32_t energy,
                     uint32_t avgPower) {
  ar->ar_wrap.schemaId = OBJECT_ACMEREPORT_DIGEST;
  // we'll always include all the records, so set the length to be the length of six kv pairs
  ar->ar_wrap.object.ACmeReport_len =   sizeof(nx_struct object_kv_ACmeReport_period) +
    sizeof(nx_struct object_kv_ACmeReport_minPower) +
    sizeof(nx_struct object_kv_ACmeReport_maxPower) +
    sizeof(nx_struct object_kv_ACmeReport_instPower) +
    sizeof(nx_struct object_kv_ACmeReport_energy) +
    sizeof(nx_struct object_kv_ACmeReport_avgPower);

  // need to identify the keys, so use the enums.
  ar->ar_period.key = OBJECT_KEY_period;
  ar->ar_minPower.key = OBJECT_KEY_minPower;
  ar->ar_maxPower.key = OBJECT_KEY_maxPower;
  ar->ar_instPower.key = OBJECT_KEY_instPower;
  ar->ar_energy.key = OBJECT_KEY_energy;
  ar->ar_avgPower.key = OBJECT_KEY_avgPower;

  // finally, fill in the data
  ar->ar_period.period = period;
  ar->ar_minPower.minPower = minPower;
  ar->ar_maxPower.maxPower = maxPower;
  ar->ar_instPower.instPower = instPower;
  ar->ar_energy.energy = energy;
  ar->ar_avgPower.avgPower = avgPower;
  return 0;
}

void do_test(char *name, int i1, int i2, int i3, int i4, int i5, int i6) {
  nx_struct ACmeReport ar;
  FILE *fp = fopen(name, "w");
  if (fp == NULL) {
    perror(name);
    return;
  }
  ACmeReport_build(&ar, i1,i2,i3,i4,i5,i6);
  fwrite(&ar, sizeof(nx_struct ACmeReport), 1, fp);
  fclose(fp);
}
  
int main(int argc, char **argv) {
  do_test("test1", 0,1,2,3,4,5);
  do_test("test2", 10,20,30,40,50,60);
  do_test("test3", 100,200,300,400,500,600);
  do_test("test4", 3,5,7,11,13,17);
  do_test("test5", 48,48,49,50,51,52);
  return 0;
}

