#include "tracer.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <utility>

#include "event.h"
#include "handler.h"
#include "log.h"
#include "syscalls.h"
#include "tracee.h"

using namespace std;

#define PTRACE(req, pid, addr, data)                            \
  ({                                                            \
    long v;                                                     \
    if ((v = ptrace(PTRACE_ ## req, pid, addr, data)) == -1) {  \
      fprintf(stderr, "%s:%d: ptrace(%s, %d) failed: %s\n",     \
              __FILE__, __LINE__, #req, pid, strerror(errno));  \
      abort();                                                  \
    }                                                           \
    v;                                                          \
  })

namespace katd {

Tracer::Tracer(char** argv)
  : argv_(argv),
    pid_(-1),
    follow_children_(false),
    is_in_syscall_(false) {
  tracee_ = Tracee::create(argv_[0]);
}

Tracer::~Tracer() {
}

Tracer::ProcessState::ProcessState()
  : status(0),
    execve_handled(false) {
}

void Tracer::addHandler(Handler* handler) {
  handlers_.push_back(handler);
}

void Tracer::run() {
  attach();

  int opts = 0;
#ifdef USE_SECCOMP
  opts |= PTRACE_O_TRACESECCOMP;
#endif
  if (follow_children_) {
    opts |= PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
  }
  PTRACE(SETOPTIONS, pid_, 0, opts);

  while (!pids_.empty()) {
#ifdef USE_SECCOMP
      if (is_in_syscall_)
        PTRACE(SYSCALL, pid_, 0, 0);
      else
        PTRACE(CONT, pid_, 0, 0);
#else
      PTRACE(SYSCALL, pid_, 0, 0);
#endif
    if (!wait()) {
      continue;
    }
    handleSyscall();
  }
}

static string normalizeDir(string cwd) {
  while (!cwd.empty() && cwd[cwd.size() - 1] == '/')
    cwd.resize(cwd.size() - 1);
  cwd.push_back('/');
  return cwd;
}

void Tracer::attach() {
  root_pid_ = pid_ = fork();
  PCHECK(pid_ >= 0);
  if (pid_ == 0) {
    PTRACE(TRACEME, 0, 0, 0);
#ifdef USE_SECCOMP
    PCHECK(tracee_->setupSeccomp());
#endif
    PCHECK(execvp(argv_[0], argv_) == 0);
  }

  pids_.insert(pid_);
  ProcessState* state = &states_[pid_];
  char cwd_buf[PATH_MAX + 1];
  PCHECK(getcwd(cwd_buf, PATH_MAX + 1));
  state->cwd = normalizeDir(cwd_buf);
  for (char** p = argv_; *p; p++)
    state->args.push_back(*p);

  if (!wait()) {
    fprintf(stderr, "failed to run the binary: %s\n", argv_[0]);
    abort();
  }
}

bool Tracer::wait() {
  int status;
  pid_ = ::wait(&status);
  PCHECK(pid_ >= 0);

  std::map<int, ProcessState>::iterator found = states_.find(pid_);
  if (found != states_.end())
    found->second.status = status;

#ifdef USE_SECCOMP
  if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
    return true;
  }
#endif

  if (!WIFSTOPPED(status)) {
    pids_.erase(pid_);
    if (pids_.empty())
      return false;
    return wait();
  }

  int sig = WSTOPSIG(status);
  if (sig != SIGTRAP && sig != (SIGTRAP | SI_KERNEL) &&
      sig != SIGSTOP && sig != SIGTSTP && sig != SIGTTIN && sig != SIGTTOU) {
    siginfo_t siginfo;
    if (ptrace(PTRACE_GETSIGINFO, pid_, 0, &siginfo) >= 0) {
      // This is signal-delivery-stop. Deliver the signal to the tracee.
      PTRACE(SYSCALL, pid_, 0, sig);
    }
    return wait();
  }

  return true;
}

void Tracer::handleSyscall() {
  PTRACE(GETREGS, pid_, 0, tracee_->getRegisterBuffer());
  Event ev;
  ev.pid = pid_;
  ev.syscall = tracee_->getSyscall();
  int64_t retval = tracee_->getReturnValue();
  ev.error = 0;
  if (-4096 < retval && retval < 0)
    ev.error = -retval;

#if 0
  fprintf(stderr, "stop %s(%d) %ld %ld %ld => %ld\n",
          getSyscallName(ev.syscall), ev.syscall,
          tracee_->getArgument(0),
          tracee_->getArgument(1),
          tracee_->getArgument(2),
          retval);
#endif

  is_in_syscall_ = (retval == -ENOSYS);
  // Do not care the syscall entrace and uninteresting syscalls.
  // However, we need to check the arguments of execve at its entrance.
  if ((is_in_syscall_ && ev.syscall != SYSCALL_EXECVE) ||
      ev.syscall == UNINTERESTING_SYSCALL)
    return;

  int at_fd = AT_FDCWD;
  int at_fd_arg_index = 0;
  switch (ev.syscall) {
  case SYSCALL_SYMLINKAT:
    at_fd_arg_index = 1;
    goto peek_at_fd;

  case SYSCALL_FACCESSAT:
  case SYSCALL_FCHMODAT:
  case SYSCALL_FCHOWNAT:
  case SYSCALL_FSTATAT:
  case SYSCALL_FUTIMESAT:
  case SYSCALL_LINKAT:
  case SYSCALL_MKDIRAT:
  case SYSCALL_MKNODAT:
  case SYSCALL_OPENAT:
  case SYSCALL_READLINKAT:
  case SYSCALL_RENAMEAT:
  case SYSCALL_UNLINKAT:
  case SYSCALL_UTIMENSAT:
  peek_at_fd:
    at_fd = tracee_->getArgument(at_fd_arg_index);
    break;

  default:
    break;
  }

  int path_arg_index = getPathArgIndex(ev.syscall);
  if (path_arg_index >= 0) {
    peekPathArgument(path_arg_index, at_fd, &ev.path);
    //fprintf(stderr, "%s %s\n", getSyscallName(ev.syscall), ev.path.c_str());
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
  case SYSCALL_SYMLINK:
  case SYSCALL_SYMLINKAT:
  case SYSCALL_TRUNCATE:
    ev.type = WRITE_CONTENT;
    break;

  case SYSCALL_RMDIR:
  case SYSCALL_UNLINK:
  case SYSCALL_UNLINKAT:
    ev.type = REMOVE_CONTENT;
    break;

  case SYSCALL_CHDIR:
    ev.type = READ_METADATA;
    if (!ev.error)
      states_[pid_].cwd = normalizeDir(ev.path);
    break;

  case SYSCALL_CHROOT:
    break;
  case SYSCALL_CLONE:
    handleClone(retval);
    break;
  case SYSCALL_EXECVE:
    handleExecve(&ev);
    break;

  case SYSCALL_FORK:
  case SYSCALL_VFORK:
    handleFork(retval);
    break;

  case SYSCALL_LINK:
  case SYSCALL_LINKAT:
    handleLink(&ev);
    break;

  case SYSCALL_OPEN:
  case SYSCALL_OPENAT:
    handleOpen(&ev, retval);
    break;

  case SYSCALL_RENAME:
  case SYSCALL_RENAMEAT:
    handleRename(&ev);
    break;

  case SYSCALL_USELIB:
    // We do not support uselib.
    assert(0);
  case UNINTERESTING_SYSCALL:
    assert(0);
  }

  if (ev.type != INVALID_EVENT_TYPE) {
    if (ev.error) {
      switch (ev.type) {
      case READ_CONTENT:
      case READ_METADATA:
      case REMOVE_CONTENT:
        ev.type = READ_FAILURE;
        break;
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

bool Tracer::peekPathArgument(int arg, int at_fd, string* path) {
  if (!peekStringArgument(arg, path))
    return false;
  if ((*path)[0] != '/') {
    if (at_fd == AT_FDCWD) {
      *path = states_[pid_].cwd + *path;
    } else {
      const ProcessState& state = states_[pid_];
      map<int, string>::const_iterator found = state.fds.find(at_fd);
      if (found != state.fds.end()) {
        *path = normalizeDir(found->second) + *path;
      } else {
        *path = "<bad fd>/" + *path;
      }
    }
  }
  return true;
}

void Tracer::sendEvent(const Event& event) {
  for (size_t i = 0; i < handlers_.size(); i++)
    handlers_[i]->handleEvent(event);
}

void Tracer::handleOpen(Event* ev, int fd) {
  assert(ev->syscall == SYSCALL_OPEN || ev->syscall == SYSCALL_OPENAT);
  if (fd >= 0) {
    states_[pid_].fds[fd] = ev->path;
  }

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

void Tracer::handleClone(int pid) {
  int64_t flag = tracee_->getArgument(0);
  if (flag & CLONE_THREAD)
    return;
  handleFork(pid);
}

void Tracer::handleFork(int pid) {
  if (!follow_children_ || pid <= 0)
    return;
  CHECK(pids_.insert(pid).second);
  states_[pid].args = states_[pid_].args;
  states_[pid].cwd = states_[pid_].cwd;
}

void Tracer::handleExecve(Event* ev) {
  ProcessState* state = &states_[pid_];
  if (ev->error == ENOSYS) {
    vector<string>* args = &state->args;
    args->clear();
    args->push_back(ev->path);
    // TODO(hamaji): Copy all arguments.
    state->execve_handled = false;
  } else if (!state->execve_handled) {
    // We stop three times (syscall-enter-stop, execve-stop, and
    // syscall-exit-stop) for a single execve. Ignore the last stop by
    // checking execve_handled.
    ev->path = state->args[0];
    ev->type = READ_CONTENT;
    state->execve_handled = true;
  }
}

void Tracer::handleRename(Event* ev) {
  assert(ev->syscall == SYSCALL_RENAME || ev->syscall == SYSCALL_RENAMEAT);
  ev->type = ev->error ? READ_FAILURE : REMOVE_CONTENT;
  sendEvent(*ev);
  ev->type = WRITE_CONTENT;
  ev->path.clear();
  int64_t newpath_arg_index = ev->syscall == SYSCALL_RENAME ? 1 : 2;
  peekPathArgument(newpath_arg_index, AT_FDCWD, &ev->path);
}

void Tracer::handleLink(Event* ev) {
  assert(ev->syscall == SYSCALL_LINK || ev->syscall == SYSCALL_LINKAT);
  ev->type = ev->error ? READ_FAILURE : READ_METADATA;
  sendEvent(*ev);
  ev->type = WRITE_CONTENT;
  ev->path.clear();
  int64_t newpath_arg_index = ev->syscall == SYSCALL_LINK ? 1 : 3;
  peekPathArgument(newpath_arg_index, AT_FDCWD, &ev->path);
}

}  // namespace katd
