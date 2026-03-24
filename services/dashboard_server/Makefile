CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -I/usr/include/postgresql
LDFLAGS = -lpq -lboost_system -lpthread

all: dashboard_server

dashboard_server: dashboard_server.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f dashboard_server
