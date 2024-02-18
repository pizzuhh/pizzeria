CXX=g++
CXXFLAGS=-lcurl -luuid

BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -DCRYPTO -lcrypto
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -DCRYPTO -lcrypto

build-no-encrypt:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -lcrypto -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -lcrypto -g

clean:
	rm -rf $(BUILD)/*

