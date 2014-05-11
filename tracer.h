#ifndef KATD_TRACER_H_
#define KATD_TRACER_H_

#include <map>
#include <set>
#include <string>
#include <vector>

namespace katd {

class Event;
class Handler;
class Tracee;

class Tracer {
public:
  Tracer(char** argv);
  ~Tracer();

  void addHandler(Handler* handler);
  void run();

  void set_follow_children(bool f) { follow_children_ = f; }

private:
  struct ProcessState {
    ProcessState();
    std::vector<std::string> args;
    int status;
    bool execve_handled;
  };

  bool wait();
  void handleSyscall();
  bool peekStringArgument(int arg_index, std::string* path) const;
  void sendEvent(const Event& event);

  void handleOpen(Event* ev);
  void handleClone(int pid);
  void handleFork(int pid);
  void handleExecve(Event* ev);
  void handleRename(Event* ev);
  void handleLink(Event* ev);

  Tracee* tracee_;
  char** argv_;
  int root_pid_;
  int pid_;
  std::vector<Handler*> handlers_;
  bool follow_children_;
  std::set<int> pids_;
  std::map<int, ProcessState> states_;
};

}  // namespace katd

#endif  // KATD_TRACER_H_
