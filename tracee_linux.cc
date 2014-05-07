#include "tracee.h"

#include <stdint.h>

class Tracee_x86_64 : public Tracee {
public:
  virtual void* getRegisterBuffer() {
    return &registers_;
  }

  virtual int getSyscall() const {
    return registers_.orig_rax;
  }

private:
  struct Registers {
    uint64_t  r15, r14, r13, r12, rbp, rbx, r11, r10;
    uint64_t  r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
    uint64_t  rip, cs, eflags;
    uint64_t  rsp, ss;
    uint64_t  fs_base,  gs_base;
    uint64_t  ds, es, fs, gs;
  };

  Registers registers_;
};

Tracee* Tracee::create(const char* filename) {
  return new Tracee_x86_64();
}

Tracee::~Tracee() {}
