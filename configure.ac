AC_INIT([udpReplay], [1.0.1])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC

# For Solaris
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_CHECK_LIB([socket], [connect])

AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h net/ethernet.h sys/ethernet.h])
AC_CHECK_MEMBERS([struct udphdr.uh_ulen,
		  struct udphdr.uh_dport,
		  struct udphdr.len,
		  struct udphdr.dest], [], [], [
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <netinet/udp.h>
])

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
