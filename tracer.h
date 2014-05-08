#ifndef KATD_TRACER_H_
#define KATD_TRACER_H_

#include <string>

class Tracee;

class Tracer {
public:
  Tracer(char** argv);
  ~Tracer();

  void run();

  int status() const { return status_; }

private:
  bool wait();
  void handleSyscall();
  bool peekStringArgument(int arg_index, std::string* path) const;

  Tracee* tracee_;
  char** argv_;
  int pid_;
  int status_;
};

#endif  // KATD_TRACER_H_
