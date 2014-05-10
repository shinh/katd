#include "tracer.h"

#include <assert.h>
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

#include "event.h"
#include "handler.h"
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

Tracer::~Tracer() {
  for (size_t i = 0; i < handlers_.size(); i++)
    delete handlers_[i];
}

void Tracer::addHandler(Handler* handler) {
  handlers_.push_back(handler);
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

  EventType type = INVALID_EVENT_TYPE;
  switch (syscall) {
  case SYSCALL_ACCESS:
  case SYSCALL_FACCESSAT:
  case SYSCALL_FSTATAT:
  case SYSCALL_LSTAT:
  case SYSCALL_READLINK:
  case SYSCALL_READLINKAT:
  case SYSCALL_STAT:
  case SYSCALL_STATFS:
    type = READ_METADATA;
    break;

  case SYSCALL_ACCT:
  case SYSCALL_CHMOD:
  case SYSCALL_CHOWN:
  case SYSCALL_FCHMODAT:
  case SYSCALL_FCHOWNAT:
  case SYSCALL_FUTIMESAT:
  case SYSCALL_LCHOWN:
  case SYSCALL_UTIME:
  case SYSCALL_UTIMENSAT:
    type = WRITE_METADATA;
    break;

  case SYSCALL_CREAT:
  case SYSCALL_MKDIR:
  case SYSCALL_MKDIRAT:
  case SYSCALL_MKNOD:
  case SYSCALL_MKNODAT:
    type = WRITE_CONTENT;
    break;

  case SYSCALL_CHDIR:
    break;
  case SYSCALL_CHROOT:
    break;
  case SYSCALL_CLONE:
    break;
  case SYSCALL_EXECVE:
    break;
  case SYSCALL_FORK:
    break;

  case SYSCALL_LINK:
    break;
  case SYSCALL_LINKAT:
    break;

  case SYSCALL_OPEN:
    break;
  case SYSCALL_OPENAT:
    break;

  case SYSCALL_RENAME:
    break;
  case SYSCALL_RENAMEAT:
    break;
  case SYSCALL_RMDIR:
    break;

  case SYSCALL_SYMLINK:
    break;
  case SYSCALL_SYMLINKAT:
    break;
  case SYSCALL_TRUNCATE:
    break;
  case SYSCALL_UNLINK:
    break;
  case SYSCALL_UNLINKAT:
    break;

  case SYSCALL_USELIB:
    // We do not support uselib.
    assert(0);
  case SYSCALL_VFORK:
    break;
  case UNINTERESTING_SYSCALL:
    assert(0);
  }

  if (type != INVALID_EVENT_TYPE) {
    if (-4096 < retval && retval < 0) {
      switch (type) {
      case READ_CONTENT:
      case READ_METADATA:
        type = READ_FAILURE;
        break;
      case REMOVE_CONTENT:
      case WRITE_CONTENT:
      case WRITE_METADATA:
        type = WRITE_FAILURE;
        break;
      default:
        assert(0);
      }
    }

    Event event;
    event.path = path;
    event.syscall = syscall;
    event.type = type;
    for (size_t i = 0; i < handlers_.size(); i++)
      handlers_[i]->handleEvent(event);
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
