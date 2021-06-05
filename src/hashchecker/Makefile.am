
LIBS = @LIBS@

AM_CPPFLAGS = $(CPPFLAGS)
AM_CPPFLAGS += -I$(top_srcdir) -I$(srcdir) -I../common
AM_CPPFLAGS += -Werror -Wall -Wextra

bin_PROGRAMS = hashchecker

hashchecker_SOURCES = hashchecker.cpp server.cpp context.cpp parser.cpp ../common/sha256.cpp ../common/md5.cpp ../common/util.cpp\
 server.h context.h parser.h ../common/util.h ../common/sha256.h ../common/sha256-inline.h ../common/md5.h ../common/md5-inline.h

