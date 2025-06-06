QT       += core gui network
LIBS     += -lssl -lcrypto

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    registerdialog.cpp \
    sm2_utils.cpp

HEADERS += \
    mainwindow.h \
    registerdialog.h \
    sm2_utils.h

FORMS += \
    mainwindow.ui \
    registerdialog.ui

INCLUDEPATH += /usr/include

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
