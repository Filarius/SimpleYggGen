CXX := g++
SYS = $(shell $(CXX) -dumpmachine)

STATIC := no
DEBUG  := no

SYG_SRC = main.cpp x25519.cpp sha512.cpp 
SYGCPP  = _build/sygcpp

#CXXFLAGS := -march=core2
CXXFLAGS := -march=native
#CXXFLAGS += -mtune=native
ifeq ($(DEBUG),yes)
	CXXFLAGS += -g
	CXXFLAGS += -O3
#	CXXFLAGS += -g -Og
else
	#CXXFLAGS += -O3
	CXXFLAGS += -mtune=native

	CXXFLAGS += -Ofast
	#CXXFLAGS += -pipe
	CXXFLAGS += -funroll-loops
	LDFLAGS := -s
	#LDFLAGS += -fprofile-generate
endif



SYG_OBJS = $(patsubst %.cpp,_build/obj/%.o,$(SYG_SRC))

ifneq (, $(findstring mingw, $(SYS))$(findstring cygwin, $(SYS)))
	include Makefile.mingw
else
	ifeq ($(STATIC),yes)
		LIBPATH = /usr/lib/$(SYS)
		LDLIBS  = -pthread $(LIBPATH)/libsodium.a   -lpthread -ldl -;
	else
		LDLIBS = -lsodium -lpthread
	endif
endif

all: mk_obj_dir $(SYGCPP)

mk_obj_dir:
	@mkdir -p _build/obj/windows

clean:
	$(RM) -r _build/obj $(SYGCPP)

_build/obj/%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(SYGCPP): $(SYG_OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)


.PHONY: all
.PHONY: clean
.PHONY: mk_obj_dir