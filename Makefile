# Compiler and basic compile flags
CXX        = g++
CXXFLAGS   = -Wall -Wextra -O2 -std=c++17

# Determine architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    SRC = main.cpp lexer.cpp parser.cpp aarch.cpp
else
    SRC = main.cpp lexer.cpp parser.cpp intel.cpp
endif


# Default target
all: 
	$(CXX) $(CXXFLAGS) $(SRC) -o compile
