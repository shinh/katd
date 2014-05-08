#ifndef KATD_SYSCALLS_H_
#define KATD_SYSCALLS_H_

enum Syscall {
  UNINTERESTING_SYSCALL,
#define DEFINE_SYSCALL(x, p) SYSCALL_ ## x,
#include "syscalls.tab"
#undef DEFINE_SYSCALL
};

const char* getSyscallName(Syscall s);

int getPathArgIndex(Syscall s);

#endif  // KATD_SYSCALLS_H_
