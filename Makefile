CXX=g++
CXXFLAGS=-luuid

BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -g 

clean:
	rm -rf $(BUILD)/*

