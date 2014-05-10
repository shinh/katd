#include "dump_handler.h"

#include <stdio.h>

#include <string>

#include "event.h"
#include "handler.h"
#include "syscalls.h"

using namespace std;

void DumpHandler::handleEvent(const Event& event) {
  string output;
  output += "<>![]()"[event.type];
  output += ' ';
  output += getSyscallName(event.syscall);
  output += ' ';
  output += event.path;
  fprintf(stderr, "%s\n", output.c_str());
}
