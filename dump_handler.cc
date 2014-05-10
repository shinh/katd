#include "dump_handler.h"

#include <stdio.h>

#include <sstream>
#include <string>

#include "event.h"
#include "handler.h"
#include "syscalls.h"

using namespace std;

namespace katd {

void DumpHandler::handleEvent(const Event& event) {
  ostringstream oss;
  if (show_pid_)
    oss << event.pid << ' ';
  oss << "<>![]()"[event.type];
  oss << ' ';
  oss << getSyscallName(event.syscall);
  oss << ' ';
  oss << event.path;
  fprintf(stderr, "%s\n", oss.str().c_str());
}

}  // namespace katd
