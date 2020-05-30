QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

LIBS += -L/usr/lib//usr/lib/x86_64-linux-gnu/ -lcryptopp
# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    FileSharingClient/filesharingclient.cpp \
    MinorDialogs/ServerInfoDialog/serverinfodialog.cpp \
    TcpClient/downloadfiletask.cpp \
    TcpClient/tcpclient.cpp \
    Widgets/MainTable/maintable.cpp \
    Widgets/RenamingLine/renamingline.cpp \
    eccryptopp/eccryptopp.cpp \
    util/util.cpp \
    main.cpp

HEADERS += \
    FileSharingClient/filesharingclient.h \
    MinorDialogs/ServerInfoDialog/serverinfodialog.h \
    TcpClient/downloadfiletask.h \
    TcpClient/tcpclient.h \
    Widgets/MainTable/maintable.h \
    Widgets/RenamingLine/renamingline.h \
    eccryptopp/eccryptopp.h \
    util/util.h \
    ui_main.h

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
