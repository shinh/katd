#ifndef KATD_EVENT_H_
#define KATD_EVENT_H_

#include "syscalls.h"

#include <string>

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
};

#endif  // KATD_EVENT_H_
