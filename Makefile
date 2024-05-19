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
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client $(LDFLAGS) -lcrypto -s
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server $(LDFLAGS) -lcrypto -s
server-only:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server $(LDFLAGS) -lcrypto -s
client-only:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client $(LDFLAGS) -lcrypto -s
debug:
	mkdir -p $(BUILD)
	$(CXX) $(DBCXXFLAGS) -DDEBUG ./src/client.cpp -o $(BUILD)/client-debug $(LDFLAGS) -lcrypto -g
	$(CXX) $(DBCXXFLAGS) -DDEBUG ./src/server.cpp -o $(BUILD)/server-debug $(LDFLAGS) -lcrypto -g
debug-server-only:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -DDEBUG ./src/server.cpp -o $(BUILD)/server $(LDFLAGS) -lcrypto -s
debug-client-only:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) -DDEBUG ./src/client.cpp -o $(BUILD)/client $(LDFLAGS) -lcrypto -s


clean:
	rm -rf $(BUILD)/*

