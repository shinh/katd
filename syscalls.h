#ifndef KATD_SYSCALLS_H_
#define KATD_SYSCALLS_H_

enum Syscall {
  UNINTERESTING_SYSCALL,
#define DEFINE_SYSCALL(x) SYSCALL_ ## x,
#include "syscalls.tab"
#undef DEFINE_SYSCALL
};

const char* getSyscallName(Syscall s);

#endif  // KATD_SYSCALLS_H_
