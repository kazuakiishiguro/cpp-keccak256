NAME = keccak256
SRC = keccak256.cc
OBJS = main.o

CC = g++
CFLAGS = -std=c++20 -Wall

$(NAME): $(OBJS) $(SRC)
	$(CXX) -o $@ $? $(LDFLAGS)

clean:
	rm -f $(DIST) $(OBJS) $(NAME)
