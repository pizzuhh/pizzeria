CXX=g++
CXXFLAGS=-lcurl -luuid -Wno-deprecated-declarations

BUILD=./build

all: build

.PHONY: all build debug clean

build:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -DCRYPTO -lcrypto -s -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/libpng16 -I/usr/include/libmount -I/usr/include/blkid -I/usr/include/sysprof-6 -pthread -lnotify -lgdk_pixbuf-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0

build-no-encrypt:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client -g -s -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/libpng16 -I/usr/include/libmount -I/usr/include/blkid -I/usr/include/sysprof-6 -pthread -lnotify -lgdk_pixbuf-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server -g -s

debug:
	mkdir -p $(BUILD)
	$(CXX) $(CXXFLAGS) ./src/client.cpp -o $(BUILD)/client-debug -DCRYPTO -lcrypto -g -I/usr/include/gdk-pixbuf-2.0 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/libpng16 -I/usr/include/libmount -I/usr/include/blkid -I/usr/include/sysprof-6 -pthread -lnotify -lgdk_pixbuf-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0
	$(CXX) $(CXXFLAGS) ./src/server.cpp -o $(BUILD)/server-debug -DCRYPTO -lcrypto -g

clean:
	rm -rf $(BUILD)/*

