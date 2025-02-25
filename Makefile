# Compiler and basic compile flags
CXX        = g++
CXXFLAGS   = -Wall -Wextra -O2 -std=c++17

# Name of the final compiler executable
EXEC = compile

# List of source files (adjust as needed)
SRC  = main.cpp lexer.cpp parser.cpp

# Object files (replace .cpp with .o)
OBJ  = $(SRC:.cpp=.o)

# Default target
all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -o $@
	rm -f $(OBJ)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
