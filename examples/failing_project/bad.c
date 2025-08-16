#include <stdio.h>
#include <string.h>

char buf[16];

int main(void) {
  /* Read input safely */
  if (fgets(buf, sizeof(buf), stdin) == NULL) {
    return 1; /* handle read failure */
  }

  /* Strip trailing newline if present */
  buf[strcspn(buf, "\n")] = '\0';

  printf("%s\n", buf);
  return 0;
}
