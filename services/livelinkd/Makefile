CXX=g++
CXXFLAGS=-std=c++17 -O2 -Wall -DDEBUG -Wextra -I/usr/include/postgresql
LIBS=-lpq -lboost_system -lpthread

all: livelinkd

livelinkd: livelinkd.cpp
	$(CXX) $(CXXFLAGS) livelinkd.cpp -o livelinkd $(LIBS)

clean:
	rm -f livelinkd

