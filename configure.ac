AC_INIT([udpReplay], [1.0.0])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
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
