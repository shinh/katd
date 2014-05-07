EXES=libkatd.a katd

CXXFLAGS=$(GCCFLAGS) -W -Werror -fPIC

all: $(EXES)

katd: main.o libkatd.a
	$(CXX) $^ -o $@ -g

libkatd.a: tracer.o tracee_linux.o
	ar crus $@ $^

clean:
	rm -f *.o *.d */*.o */*.d $(EXES)

-include *.d
