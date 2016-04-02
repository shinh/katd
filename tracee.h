#ifndef KATD_TRACEE_H_
#define KATD_TRACEE_H_

#include <stdint.h>

#include "syscalls.h"

namespace katd {

class Tracee {
public:
  static Tracee* create(const char* filename);
  virtual ~Tracee();

  virtual void* getRegisterBuffer() = 0;
  virtual Syscall getSyscall() const = 0;
  virtual int64_t getReturnValue() const = 0;
  virtual int64_t getArgument(int n) const = 0;
  virtual bool setupSeccomp() const { return false; }
};

}  // namespace katd

#endif  // KATD_TRACEE_H_
