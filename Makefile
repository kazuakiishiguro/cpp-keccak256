NAME = keccak256
LIB = libkeccak256.a

CXX = g++
CXXFLAGS = -std=c++20 -Wall

.PHONY: all test clean

all: $(LIB) $(NAME)

$(LIB): keccak256.o
	ar rcs $@ $^

$(NAME): test.o $(LIB)
	$(CXX) $(CXXFLAGS) -o $@ test.o -L. -lkeccak256

keccak256.o: keccak256.cc keccak256.h
	$(CXX) $(CXXFLAGS) -c -o $@ keccak256.cc

test.o: test.cc keccak256.h
	$(CXX) $(CXXFLAGS) -c -o $@ test.cc

test: $(NAME)
	./$(NAME)

clean:
	rm -f *.o $(LIB) $(NAME)
