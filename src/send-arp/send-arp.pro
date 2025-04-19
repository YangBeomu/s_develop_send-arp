QT = core

CONFIG += c++17 cmdline
LIBS += -lpcap
#INCLUDEPATH += $$PWD/../../include

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        ../../include/ethhdr.cpp \
        ../../include/ip.cpp \
        ../../include/mac.cpp \
        ../../include/networkcontroller.cpp \
        main.cpp

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    ../../include/arphdr.hpp \
    ../../include/ethhdr.h \
    ../../include/ip.h \
    ../../include/iphdr.hpp \
    ../../include/mac.h \
    ../../include/networkcontroller.h \
    ../../include/tcphdr.hpp
