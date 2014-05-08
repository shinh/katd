#include "syscalls.h"

static const char* SYSCALL_NAMES[] = {
  "???",
#define DEFINE_SYSCALL(x) #x,
#include "syscalls.tab"
#undef DEFINE_SYSCALL
};

const char* getSyscallName(Syscall s) {
  return SYSCALL_NAMES[s];
}
