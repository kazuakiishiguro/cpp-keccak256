NAME = keccak256
OBJS = main.o

CC = g++
CFLAGS = -std=c++20 -Wall

$(NAME): $(OBJS)
	$(CXX) -o $@ $? $(LDFLAGS)

clean:
	rm -f $(DIST) $(OBJS) $(NAME)
