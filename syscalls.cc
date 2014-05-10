#include "syscalls.h"

#include <assert.h>

namespace katd {

static const char* SYSCALL_NAMES[] = {
  "???",
#define DEFINE_SYSCALL(x, p) #x,
#include "syscalls.tab"
#undef DEFINE_SYSCALL
};

const char* getSyscallName(Syscall s) {
  return SYSCALL_NAMES[s];
}

int getPathArgIndex(Syscall s) {
  switch (s) {
  case UNINTERESTING_SYSCALL:
    return -1;
#define DEFINE_SYSCALL(x, p) case SYSCALL_ ## x: return p;
#include "syscalls.tab"
#undef DEFINE_SYSCALL
  default:
    assert(0);
  }
}

}  // namespace katd
