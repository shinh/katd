#include <stdio.h>
#include <string.h>

#include "dump_handler.h"
#include "tracer.h"

int main(int argc, char* argv[]) {
  const char* arg0 = argv[0];
  bool follow_children = false;
  if (!strcmp(argv[1], "-f")) {
    follow_children = true;
    argc--;
    argv++;
  }
  if (argc < 2) {
    fprintf(stderr, "Usage: %s command [arg ...]\n", arg0);
    return 1;
  }

  katd::Tracer tracer(argv + 1);
  tracer.set_follow_children(follow_children);

  katd::DumpHandler dump_handler;
  dump_handler.set_show_pid(follow_children);

  tracer.addHandler(&dump_handler);
  tracer.run();
}
