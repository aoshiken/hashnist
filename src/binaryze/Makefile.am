
LIBS = @LIBS@

AM_CPPFLAGS = $(CPPFLAGS)
AM_CPPFLAGS += -I$(top_srcdir) -I$(srcdir) -I../common
AM_CPPFLAGS += -Werror -Wall -Wextra

bin_PROGRAMS = binaryze

binaryze_SOURCES = binaryze.cpp parser.cpp ../common/util.cpp ../common/sha256.cpp ../common/md5.cpp

