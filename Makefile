# Compiler and basic compile flags
CXX        = g++
CXXFLAGS   = -Wall -Wextra -O2 -std=c++17

# Determine architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),arm64)
    SRC = ignore.cpp lexer.cpp parser.cpp
else
    SRC = main.cpp lexer.cpp parser.cpp
endif

# Object files (replace .cpp with .o)
OBJ  = $(SRC:.cpp=.o)

# Name of the final compiler executable
EXEC = compile

# Default target
all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -o $@
	rm -f $(OBJ)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
