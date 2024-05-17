TEMPLATE=app
TARGET=pizzeria
INCLUDEPATH += .

HEADERS += $$files(src-ui/*.hpp)
SOURCES += $$files(src-ui/*.cpp)
FORMS += $$files(src-ui/*.ui)

QT += widgets

# Additional configurations
CONFIG += c++11

DESTDIR = ./build
OBJECTS_DIR = ./build/obj
MOC_DIR = ./build/moc
UI_DIR = ./build/ui
RCC_DIR = ./build/rcc
