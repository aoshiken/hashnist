
LIBS = @LIBS@

AM_CPPFLAGS = $(CPPFLAGS)
AM_CPPFLAGS += -I$(top_srcdir) -I$(srcdir) -I../common
AM_CPPFLAGS += -Werror -Wall -Wextra

bin_PROGRAMS = binaryzemd5

binaryzemd5_SOURCES = binaryze.cpp parser.cpp ../common/util.cpp ../common/util.h ../common/md5.cpp ../common/md5.h

