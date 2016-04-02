#ifndef KATD_LOG_H_
#define KATD_LOG_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c)                                                        \
  if (!(c)) {                                                           \
    fprintf(stderr, "%s:%d: CHECK (%s) failed\n",                       \
            __FILE__, __LINE__, #c);                                    \
    abort();                                                            \
  }

#define PCHECK(c)                                                       \
  if (!(c)) {                                                           \
    fprintf(stderr, "%s:%d: CHECK (%s) failed: %s\n",                   \
            __FILE__, __LINE__, #c, strerror(errno));                   \
    abort();                                                            \
  }

#endif  // KATD_LOG_H_
