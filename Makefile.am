bin_PROGRAMS = udpreplay atxDepack liuDepack blockDepack
man_MANS = udpReplay.1

udpreplay_SOURCES = \
	udpReplay.c \
	udpCallback.c \
	udpCallback.h \
	asterix.h \
	asterix.c

atxDepack_SOURCES = \
	atxDepack.c

liuDepack_SOURCES = \
	liuDepack.c

blockDepack_SOURCES = \
	blockDepack.c

AM_CPPFLAGS = -I. -D_GNU_SOURCE
AM_CFLAGS = $(PCAP_CFLAGS) -Wall
LDADD = $(PCAP_LIBS)

EXTRA_DIST=udpReplay.1
