#include "tracer.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
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
      fprintf(stderr, "ptrace(%s, %d) failed: %s\n",            \
              #req, pid, strerror(errno));                      \
      abort();                                                  \
    }                                                           \
    v;                                                          \
  })

namespace katd {

Tracer::Tracer(char** argv)
  : argv_(argv),
    pid_(-1),
    status_(-1),
    follow_children_(false) {
  tracee_ = Tracee::create(argv_[0]);
}

Tracer::~Tracer() {
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

  pids_.insert(pid_);
  if (!wait()) {
    fprintf(stderr, "failed to run the binary: %s\n", argv_[0]);
    abort();
  }

  if (follow_children_) {
    PTRACE(SETOPTIONS, pid_, 0,
           PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);
  }

  while (!pids_.empty()) {
    PTRACE(SYSCALL, pid_, 0, 0);
    if (!wait()) {
      continue;
    }
    handleSyscall();
  }
}

bool Tracer::wait() {
  int pid = ::wait(&status_);
  PCHECK(pid >= 0);
  int sig = WSTOPSIG(status_) & 0xff;
  if (!WIFSTOPPED(status_) ||
      (sig != SIGTRAP && sig != SIGCHLD && sig != SIGSTOP)) {
    pids_.erase(pid);
    if (pids_.empty())
      return false;
    return wait();
  }
  pid_ = pid;
  return true;
}

void Tracer::handleSyscall() {
  PTRACE(GETREGS, pid_, 0, tracee_->getRegisterBuffer());
  Event ev;
  ev.syscall = tracee_->getSyscall();
  int64_t retval = tracee_->getReturnValue();
  ev.error = 0;
  if (-4096 < retval && retval < 0)
    ev.error = -retval;

  fprintf(stderr, "stop %s(%d) %ld %ld %ld => %ld\n",
          getSyscallName(ev.syscall), ev.syscall,
          tracee_->getArgument(0),
          tracee_->getArgument(1),
          tracee_->getArgument(2),
          retval);
  // Do not care the syscall entrace and uninteresting syscalls.
  if (retval == -ENOSYS || ev.syscall == UNINTERESTING_SYSCALL)
    return;

  int path_arg_index = getPathArgIndex(ev.syscall);
  if (path_arg_index >= 0) {
    peekStringArgument(path_arg_index, &ev.path);
    fprintf(stderr, "%s %s\n", getSyscallName(ev.syscall), ev.path.c_str());
  }

  ev.type = INVALID_EVENT_TYPE;
  switch (ev.syscall) {
  case SYSCALL_ACCESS:
  case SYSCALL_FACCESSAT:
  case SYSCALL_FSTATAT:
  case SYSCALL_LSTAT:
  case SYSCALL_READLINK:
  case SYSCALL_READLINKAT:
  case SYSCALL_STAT:
  case SYSCALL_STATFS:
    ev.type = READ_METADATA;
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
    ev.type = WRITE_METADATA;
    break;

  case SYSCALL_CREAT:
  case SYSCALL_MKDIR:
  case SYSCALL_MKDIRAT:
  case SYSCALL_MKNOD:
  case SYSCALL_MKNODAT:
    ev.type = WRITE_CONTENT;
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
  case SYSCALL_OPENAT:
    handleOpen(&ev);
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

  if (ev.type != INVALID_EVENT_TYPE) {
    if (ev.error) {
      switch (ev.type) {
      case READ_CONTENT:
      case READ_METADATA:
        ev.type = READ_FAILURE;
        break;
      case REMOVE_CONTENT:
      case WRITE_CONTENT:
      case WRITE_METADATA:
        ev.type = WRITE_FAILURE;
        break;
      default:
        assert(0);
      }
    }

    for (size_t i = 0; i < handlers_.size(); i++)
      handlers_[i]->handleEvent(ev);
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

void Tracer::sendEvent(const Event& event) {
  for (size_t i = 0; i < handlers_.size(); i++)
    handlers_[i]->handleEvent(event);
}

void Tracer::handleOpen(Event* ev) {
  assert(ev->syscall == SYSCALL_OPEN || ev->syscall == SYSCALL_OPENAT);
  int flag_arg_index = ev->syscall == SYSCALL_OPEN ? 1 : 2;
  int64_t flag = tracee_->getArgument(flag_arg_index);
  switch (flag & O_ACCMODE) {
  case O_WRONLY:
    ev->type = WRITE_CONTENT;
    break;
  case O_RDWR:
    ev->type = ev->error ? READ_FAILURE : READ_CONTENT;
    sendEvent(*ev);
    ev->type = WRITE_CONTENT;
    break;
  default:
    // If the invalid O_ACCMODE is specified, it will be READ_FAILURE.
    ev->type = READ_CONTENT;
  }
}

}  // namespace katd
