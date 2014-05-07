#include "tracer.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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

    PTRACE(GETREGS, pid_, 0, tracee_->getRegisterBuffer());
    fprintf(stderr, "stop %d\n", tracee_->getSyscall());
  }
}

bool Tracer::wait() {
  PCHECK(waitpid(pid_, &status_, 0) >= 0);
  if (!WIFSTOPPED(status_))
    return false;
  return true;
}
