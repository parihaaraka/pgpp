
TARGET = db_example

TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += c++11

SOURCES += main.cpp \
    ../pg_params.cpp \
    ../pg_result.cpp \
    ../pg_connection.cpp \
    ../pg_query.cpp

LIBS += -lpq -lev

PRE_TARGETDEPS

INCLUDEPATH += /usr/include/postgresql

HEADERS += \
    ../dbpool.h \
    ../pg_params.h \
    ../pg_result.h \
    ../pg_types.h \
    ../pg_connection.h \
    ../pg_query.h


