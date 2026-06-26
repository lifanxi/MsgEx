CC ?= gcc
CXX ?= g++
TARGET ?= qqmsg

CFLAGS ?= -O2 -g
CXXFLAGS ?= -O2 -g
CPPFLAGS ?= -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= $(shell pkg-config --libs icu-uc 2>/dev/null || echo -licuuc -licudata)

C_SRCS := BlowFish.c debug.c md5.c QQmsg_decode.c tree.c
CXX_SRCS := QQMsg.cpp
OBJS := $(C_SRCS:.c=.o) $(CXX_SRCS:.cpp=.o)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
