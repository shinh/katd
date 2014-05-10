#ifndef KATD_HANDLER_H_
#define KATD_HANDLER_H_

class Event;

class Handler {
public:
  virtual ~Handler() {}

  virtual void handleEvent(const Event& event) = 0;
};

#endif  // KATD_HANDLER_H_
