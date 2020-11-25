AC_INIT([shanist], [0.1.0], [aandreswork@hotmail.com])

AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CXX(clang++)

dnl
dnl Check for libraries
dnl
AC_CHECK_LIB(event, main, [], [AC_MSG_ERROR([Ouch!! Libevent library is needed!])])

AC_CHECK_HEADERS(event2/event.h event2/bufferevent.h, [], [AC_MSG_ERROR([Ouch!! Libevent headers are needed])])

AC_CANONICAL_HOST

AH_TEMPLATE([LINUX], [Linux System])

case "${host_os}" in

    *linux*)
        AC_DEFINE(LINUX)
        ;;

    *)
        AC_MSG_ERROR(Currently only Linux OS is supported)
        ;;

esac

AC_MSG_CHECKING(if __uint128_t are supported)
AC_TRY_RUN([
int main()
{
#ifdef __SIZEOF_INT128__
    exit(0);
#else
    exit(1);
#endif
}],
[AC_MSG_RESULT(yes); have_uint128=yes],
[AC_MSG_RESULT(no); have_uint128=no],
[AC_MSG_RESULT(no); have_uint128=no])

if test $have_uint128 = no; then
  AC_MSG_WARN(Ouch!! A Linux system with support for __uint128_t is needed in order to compile!!...)
  AC_MSG_ERROR(...i'm sure you'll take the right decision.)
fi

AC_OUTPUT(Makefile src/hashchecker/Makefile src/binaryze/Makefile)
