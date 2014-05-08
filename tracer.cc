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

#include <string>

#include "syscalls.h"
#include "tracee.h"

using namespace std;

#define PCHECK(c)                                                       \
  if (!(c)) {                                                           \
    fprintf(stderr, "CHECK (%s) failed: %s\n", #c, strerror(errno));    \
    abort();                                                            \
  }

#define PTRACE(req, pid, addr, data)                            \
  ({                                                            \
    long v;                                                     \
    if ((v = ptrace(PTRACE_ ## req, pid, addr, data)) == -1) {  \
      fprintf(stderr, "ptrace(%s) failed: %s\n",                \
              #req, strerror(errno));                           \
      abort();                                                  \
    }                                                           \
    v;                                                          \
  })

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

  int path_arg_index = getPathArgIndex(syscall);
  string path;
  if (path_arg_index >= 0) {
    peekStringArgument(path_arg_index, &path);
    fprintf(stderr, "%s %s\n", getSyscallName(syscall), path.c_str());
  }
}

bool Tracer::peekStringArgument(int arg, string* path) const {
  char* ptr = reinterpret_cast<char*>(tracee_->getArgument(arg));
  if (!ptr)
    return false;
  for (;;) {
    // TOOD(hamaji): Handle ptrace failures.
    long val = PTRACE(PEEKDATA, pid_, ptr, 0);
    path->resize(path->size() + sizeof(val));
    memcpy(&(*path)[path->size() - sizeof(val)], &val, sizeof(val));
    size_t len = strlen(path->c_str());
    if (len != path->size()) {
      path->resize(len);
      return true;
    }
    ptr += sizeof(val);
  }
}
