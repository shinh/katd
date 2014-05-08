#include "tracer.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "syscalls.h"
#include "tracee.h"

#define PCHECK(c)                                                       \
  if (!(c)) {                                                           \
    fprintf(stderr, "CHECK (%s) failed: %s\n", #c, strerror(errno));    \
    abort();                                                            \
  }

#define PTRACE(req, pid, addr, data)                    \
  if (ptrace(PTRACE_ ## req, pid, addr, data) == -1) {  \
    fprintf(stderr, "ptrace(%s) failed: %s\n",          \
            #req, strerror(errno));                     \
    abort();                                            \
  }

Tracer::Tracer(char** argv)
  : argv_(argv),
    pid_(-1),
    status_(-1) {
  tracee_ = Tracee::create(argv_[0]);
}

void Tracer::run() {
  pid_ = fork();
  PCHECK(pid_ >= 0);
  if (pid_ == 0) {
    PTRACE(TRACEME, 0, 0, 0);
    PCHECK(execvp(argv_[0], argv_) == 0);
  }

  if (!wait()) {
    fprintf(stderr, "failed to run the binary: %s\n", argv_[0]);
    abort();
  }

  for (;;) {
    PTRACE(SYSCALL, pid_, 0, 0);
    if (!wait())
      return;
    handleSyscall();
  }
}

bool Tracer::wait() {
  PCHECK(waitpid(pid_, &status_, 0) >= 0);
  if (!WIFSTOPPED(status_))
    return false;
  return true;
}

void Tracer::handleSyscall() {
  PTRACE(GETREGS, pid_, 0, tracee_->getRegisterBuffer());
  int64_t retval = tracee_->getReturnValue();
  Syscall syscall = tracee_->getSyscall();

  fprintf(stderr, "stop %s %ld %ld %ld => %ld\n",
          getSyscallName(syscall),
          tracee_->getArgument(0),
          tracee_->getArgument(1),
          tracee_->getArgument(2),
          retval);
  // Do not care the syscall entrace and uninteresting syscalls.
  if (retval == -ENOSYS || syscall == UNINTERESTING_SYSCALL)
    return;


}
