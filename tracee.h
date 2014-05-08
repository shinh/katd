#ifndef KATD_TRACEE_H_
#define KATD_TRACEE_H_

#include "syscalls.h"

class Tracee {
public:
  static Tracee* create(const char* filename);
  virtual ~Tracee();

  virtual void* getRegisterBuffer() = 0;
  virtual Syscall getSyscall() const = 0;
};

#endif  // KATD_TRACEE_H_
