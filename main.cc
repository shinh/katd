#include <stdio.h>

#include "dump_handler.h"
#include "tracer.h"

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s command [arg ...]\n", argv[0]);
    return 1;
  }

  katd::Tracer tracer(argv + 1);
  katd::DumpHandler dump_handler;
  tracer.addHandler(&dump_handler);
  tracer.run();
}
