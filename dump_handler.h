#ifndef KATD_DUMP_HANDLER_H_
#define KATD_DUMP_HANDLER_H_

#include "handler.h"

namespace katd {

class DumpHandler : public Handler {
public:
  virtual void handleEvent(const Event& event);
};

}  // namespace katd

#endif  // KATD_DUMP_HANDLER_H_
