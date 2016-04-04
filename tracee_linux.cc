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
    static const char* kSyscallNames[] = {
      "access",
      "acct",
      "chdir",
      "chmod",
      "chown",
      "chroot",
      "clone",
      "creat",
      // TODO: Catch execve.
      //"execve",
      "faccessat",
      "fchmodat",
      "fchownat",
      "fork",
      "newfstatat",
      "futimesat",
      "lchown",
      "link",
      "linkat",
      "lstat",
      "mkdir",
      "mkdirat",
      "mknod",
      "mknodat",
      "open",
      "openat",
      "readlink",
      "readlinkat",
      "rename",
      "renameat",
      "rmdir",
      "stat",
      "statfs",
      "symlink",
      "symlinkat",
      "truncate",
      "unlink",
      "unlinkat",
      "uselib",
      "utime",
      "utimes",
      "utimensat",
      "vfork",
      0,
    };
    for (const char** sys = kSyscallNames; *sys; sys++) {
      int num = seccomp_syscall_resolve_name_arch(AUDIT_ARCH_X86_64, *sys);
      PCHECK(num > 0);
      PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), num, 0) >= 0);
    }
    PCHECK(seccomp_arch_add(sctx, AUDIT_ARCH_I386) >= 0);
    for (const char** sys = kSyscallNames; *sys; sys++) {
      int num = seccomp_syscall_resolve_name_arch(AUDIT_ARCH_I386, *sys);
      // TODO: 32bit support is utterly broken.
      if (num < 0)
        continue;
      PCHECK(seccomp_rule_add(sctx, SCMP_ACT_TRACE(42), num, 0) >= 0);
    }
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
