CXX=g++
CXXFLAGS= -Wno-deprecated-declarations -Wall
LDFLAGS=-lcurl -luuid
BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -DCRYPTO $(LDFLAGS) -lcrypto -s
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -DCRYPTO $(LDFLAGS) -lcrypto -s

build-no-encrypt:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client $(LDFLAGS) -g -s
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server $(LDFLAGS) -g -s

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -DDEBUG $(LDFLAGS) -lcrypto -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -DDEBUG $(LDFLAGS) -lcrypto -g

clean:
	rm -rf $(BUILD)/*

