bin_PROGRAMS = udpreplay
man_MANS = udpReplay.1

udpreplay_SOURCES = \
	udpReplay.c \
	udpCallback.c \
	udpCallback.h

AM_CPPFLAGS = -I.
AM_CFLAGS = $(PCAP_CFLAGS) -Wall
LDADD = $(PCAP_LIBS)
