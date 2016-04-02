#USE_SECCOMP := 1

EXES := libkatd.a katd

CXXFLAGS := -g -Wall -W -Werror -fPIC -MMD -MP -O
LIBS :=
ifdef USE_SECCOMP
CXXFLAGS += -DUSE_SECCOMP
LIBS += -lseccomp
endif

all: $(EXES)

katd: main.o libkatd.a
	$(CXX) $^ -o $@ -g $(LIBS)

libkatd.a: dump_handler.o syscalls.o tracer.o tracee_linux.o
	ar crus $@ $^

clean:
	rm -f *.o *.d */*.o */*.d $(EXES)

-include *.d
