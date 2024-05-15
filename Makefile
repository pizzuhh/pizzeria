CXX=g++
CXXFLAGS= -Wall -O2  -Wno-stringop-truncation
DBCXXFLAGS=-Wall -g -O0
LDFLAGS=-lcurl -luuid
BUILD=./build
MAKEOPTS+=-j2

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
	$(CXX) $(DBCXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -DDEBUG $(LDFLAGS) -lcrypto -g
	$(CXX) $(DBCXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -DDEBUG $(LDFLAGS) -lcrypto -g

clean:
	rm -rf $(BUILD)/*

