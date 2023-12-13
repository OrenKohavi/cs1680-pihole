CXX = g++
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)

# Output file name
OUTPUT = main

# Default flags for efficient build
CXXFLAGS = -Wall -Wextra -Werror -std=c++20 -O3

# Development build flags
DEVFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fsanitize=undefined -std=c++20

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(OUTPUT) $(OBJS)

dev: CXXFLAGS = $(DEVFLAGS)
dev: $(OUTPUT)

clean:
	rm -f *.o $(OUTPUT)
