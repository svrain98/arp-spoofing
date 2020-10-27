TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
DEFINES *= GTEST
LIBS += -lgtest_main -lgtest -pthread

SOURCES += \
    arphdr.cpp \
    ethhdr.cpp \
    ip.cpp \
    atinfo.cpp \
    mac.cpp

HEADERS += \
    arphdr.h \
    ethhdr.h \
    ip.h \
    atinfo.h \
    mac.h
