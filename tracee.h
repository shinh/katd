#ifndef KATD_TRACEE_H_
#define KATD_TRACEE_H_

class Tracee {
public:
  static Tracee* create(const char* filename);
  virtual ~Tracee();

  virtual void* getRegisterBuffer() = 0;
  virtual int getSyscall() const = 0;
};

#endif  // KATD_TRACEE_H_
