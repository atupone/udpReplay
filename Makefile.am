bin_PROGRAMS = udpreplay atxDepack
man_MANS = udpReplay.1

udpreplay_SOURCES = \
	udpReplay.c \
	udpCallback.c \
	udpCallback.h \
	asterix.h \
	asterix.c

atxDepack_SOURCES = \
	atxDepack.c

AM_CPPFLAGS = -I.
AM_CFLAGS = $(PCAP_CFLAGS) -Wall
LDADD = $(PCAP_LIBS)

EXTRA_DIST=udpReplay.1
