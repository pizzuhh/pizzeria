CXX=g++
CXXFLAGS=-lcurl -luuid -Wno-deprecated-declarations

BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -DCRYPTO -lcrypto
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -DCRYPTO -lcrypto
	$(CXX) $(CXXFLAGS) ./src/clientUI.cpp -o $(BUILD)/webui -DCRYPTO -lcrypto

build-no-encrypt:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -g

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -lcrypto -g
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -lcrypto -g
	$(CXX) $(CXXFLAGS) ./src/clientUI.cpp -o $(BUILD)/webui -DCRYPTO -lcrypto -g

clean:
	rm -rf $(BUILD)/*

