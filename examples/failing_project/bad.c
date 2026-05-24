#include <stdio.h>
#include <string.h>

char buf[16];

int main(void) {
  /*
   * Intentionally unsafe example for MISRA CI demonstration.
   *
   * This file is expected to fail the MISRA CI scan.
   * It contains common unsafe C patterns that should be detected
   * by heuristic rules, such as unsafe input and unsafe formatting.
   */

  gets(buf);        /* Unsafe: no bounds checking */
  printf(buf);      /* Unsafe: format string is not controlled */

  if (strlen(buf) > 0) {
    return 0;
  }

  return 0;
}
