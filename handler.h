#ifndef KATD_HANDLER_H_
#define KATD_HANDLER_H_

namespace katd {

struct Event;

class Handler {
public:
  virtual ~Handler() {}

  virtual void handleEvent(const Event& event) = 0;
};

}  // namespace katd

#endif  // KATD_HANDLER_H_
