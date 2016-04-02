#include "tracee.h"

#include <assert.h>
#ifdef USE_SECCOMP
#include <seccomp.h>
#endif
#include <stdint.h>

#include "log.h"
#include "syscalls.h"

namespace katd {

class Tracee_x86_64 : public Tracee {
public:
  virtual void* getRegisterBuffer() {
    return &registers_;
  }

  virtual Syscall getSyscall() const {
    switch (registers_.orig_rax) {
    case 21:  // access
      return SYSCALL_ACCESS;
    case 163:  // acct
      return SYSCALL_ACCT;
    case 80:  // chdir
      return SYSCALL_CHDIR;
    case 90:  // chmod
      return SYSCALL_CHMOD;
    case 92:  // chown
      return SYSCALL_CHOWN;
    case 161:  // chroot
      return SYSCALL_CHROOT;
    case 56:  // clone
      return SYSCALL_CLONE;
    case 85:  // creat
      return SYSCALL_CREAT;
    case 59:  // execve
      return SYSCALL_EXECVE;
    case 269:  // faccessat
      return SYSCALL_FACCESSAT;
    case 268:  // fchmodat
      return SYSCALL_FCHMODAT;
    case 260:  // fchownat
      return SYSCALL_FCHOWNAT;
    case 57:  // fork
      return SYSCALL_FORK;
    case 262:  // newfstatat
      return SYSCALL_FSTATAT;
    case 261:  // futimesat
      return SYSCALL_FUTIMESAT;
    case 94:  // lchown
      return SYSCALL_LCHOWN;
    case 86:  // link
      return SYSCALL_LINK;
    case 265:  // linkat
      return SYSCALL_LINKAT;
    case 6:  // lstat
      return SYSCALL_LSTAT;
    case 83:  // mkdir
      return SYSCALL_MKDIR;
    case 258:  // mkdirat
      return SYSCALL_MKDIRAT;
    case 133:  // mknod
      return SYSCALL_MKNOD;
    case 259:  // mknodat
      return SYSCALL_MKNODAT;
    case 2:  // open
      return SYSCALL_OPEN;
    case 257:  // openat
      return SYSCALL_OPENAT;
    case 89:  // readlink
      return SYSCALL_READLINK;
    case 267:  // readlinkat
      return SYSCALL_READLINKAT;
    case 82:  // rename
      return SYSCALL_RENAME;
    case 264:  // renameat
      return SYSCALL_RENAMEAT;
    case 84:  // rmdir
      return SYSCALL_RMDIR;
    case 4:  // stat
      return SYSCALL_STAT;
    case 137:  // statfs
      return SYSCALL_STATFS;
    case 88:  // symlink
      return SYSCALL_SYMLINK;
    case 266:  // symlinkat
      return SYSCALL_SYMLINKAT;
    case 76:  // truncate
      return SYSCALL_TRUNCATE;
    case 87:  // unlink
      return SYSCALL_UNLINK;
    case 263:  // unlinkat
      return SYSCALL_UNLINKAT;
    case 134:  // uselib
      return SYSCALL_USELIB;
    case 132:  // utime
    case 235:  // utimes
      return SYSCALL_UTIME;
    case 280:  // utimensat
      return SYSCALL_UTIMENSAT;
    case 58:  // vfork
      return SYSCALL_VFORK;
    default:
      return UNINTERESTING_SYSCALL;
    }
  }

  virtual int64_t getReturnValue() const {
    return registers_.rax;
  }

  virtual int64_t getArgument(int n) const {
    switch (n) {
    case 0:
      return registers_.rdi;
    case 1:
      return registers_.rsi;
    case 2:
      return registers_.rdx;
    case 3:
      return registers_.r10;
    case 4:
      return registers_.r8;
    case 5:
      return registers_.r9;
    default:
      assert(0);
    }
  }

  virtual bool setupSeccomp() const {
#ifdef USE_SECCOMP
    scmp_filter_ctx sctx = seccomp_init(SCMP_ACT_ALLOW);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 21, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 163, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 80, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 90, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 92, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 161, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 56, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 85, 0) >= 0);
    // TODO: Catch execve.
    //PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 59, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 269, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 268, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 260, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 57, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 262, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 261, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 94, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 86, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 265, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 6, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 83, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 258, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 133, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 259, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 2, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 257, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 89, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 267, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 82, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 264, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 84, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 4, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 137, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 88, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 266, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 76, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 87, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 263, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 134, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 132, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 235, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 280, 0) >= 0);
    PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), 58, 0) >= 0);
    PCHECK(seccomp_load(sctx) >= 0);
    return true;
#else
    return false;
#endif
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

Tracee* Tracee::create(const char* /*filename*/) {
  return new Tracee_x86_64();
}

Tracee::~Tracee() {}

}  // namespace katd
