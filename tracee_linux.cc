#include "tracee.h"

#include <stdint.h>

#include "syscalls.h"

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
