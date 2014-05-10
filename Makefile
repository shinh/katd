EXES=libkatd.a katd

CXXFLAGS=-g -Wall -W -Werror -fPIC -MMD -O

all: $(EXES)

katd: main.o libkatd.a
	$(CXX) $^ -o $@ -g

libkatd.a: dump_handler.o syscalls.o tracer.o tracee_linux.o
	ar crus $@ $^

clean:
	rm -f *.o *.d */*.o */*.d $(EXES)

-include *.d
