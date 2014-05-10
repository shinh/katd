#ifndef KATD_EVENT_H_
#define KATD_EVENT_H_

#include "syscalls.h"

#include <string>

namespace katd {

enum EventType {
  INVALID_EVENT_TYPE = -1,
  READ_CONTENT,
  WRITE_CONTENT,
  REMOVE_CONTENT,
  READ_METADATA,
  WRITE_METADATA,
  READ_FAILURE,
  WRITE_FAILURE,
};

struct Event {
  std::string path;
  Syscall syscall;
  EventType type;
  int error;
};

}  // namespace katd

#endif  // KATD_EVENT_H_
