CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -g -fsanitize=address -fsanitize=undefined -std=c++20
SRCS = $(wildcard *.cpp)
OBJS = $(SRCS:.cpp=.o)

main: $(OBJS)
	$(CXX) $(CXXFLAGS) -o main $(OBJS)

clean:
	rm -f *.o main
