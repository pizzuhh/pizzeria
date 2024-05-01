CXX=g++
CXXFLAGS=-lcurl -luuid -Wno-deprecated-declarations -Wall

BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -DCRYPTO -lcrypto -s
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -DCRYPTO -lcrypto -s

build-no-encrypt:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -g -s
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -g -s

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -DDEBUG -lcrypto -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -DDEBUG -lcrypto -g

clean:
	rm -rf $(BUILD)/*

