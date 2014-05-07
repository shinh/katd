#include "tracer.h"

int main(int argc, char* argv[]) {
  Tracer tracer(argv + 1);
  tracer.run();
}
