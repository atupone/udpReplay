AC_INIT([udpReplay], [1.0.0])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC

# For Solaris
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_CHECK_LIB([socket], [connect])

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [], [
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h net/ethernet.h sys/ethernet.h])

AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strtol])
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T


AC_ARG_VAR([PCAP_HERE], [pcap-config has been found])
AC_CHECK_TOOL([PCAP_HERE], [pcap-config], [no])
if test x$PCAP_HERE == x"no" ; then
  AC_MSG_ERROR([Please install pcap before configuring udpReplay])
fi
AC_ARG_VAR([PCAP_CFLAGS], [pcap cflags])
AC_ARG_VAR([PCAP_LIBS], [pcap libraries])
PCAP_CFLAGS=$(pcap-config --cflags)
PCAP_LIBS=$(pcap-config --libs)
AC_CONFIG_FILES([
	Makefile
	])
AC_OUTPUT
