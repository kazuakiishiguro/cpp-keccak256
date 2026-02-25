NAME = keccak256
SRC = keccak256.cc
OBJS = test.o

CXX = g++
CXXFLAGS = -std=c++20 -Wall

$(NAME): $(OBJS) $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(NAME)
