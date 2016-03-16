/* udpReplay
 * Copyright (c) 2016 Tupone Alfredo
 *
 * This package is free software;  you can redistribute it and/or
 * modify it under the terms of the license found in the file
 * named COPYING that should have accompanied this file.
 *
 * THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#include "udpCallback.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <netinet/ip.h>
#include <netinet/udp.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif

static int udpSocket;
struct sockaddr_in sockaddr;
static int start_loop = 1;
char  *dvalue;
int    flood;
int    oneByOne;
long int countToFlood = 0;

void waitBeforeSending(struct timeval actual_delta)
{
  static struct timeval start_delta;

  struct timeval delta_time;
  useconds_t useconds;

  if (start_loop) {
    start_loop = 0;
    memcpy(&start_delta, &actual_delta, sizeof(struct timeval));
    return;
  }

  delta_time.tv_sec  = actual_delta.tv_sec  - start_delta.tv_sec;
  delta_time.tv_usec = actual_delta.tv_usec - start_delta.tv_usec;

  /* Normalize usec */
  if (delta_time.tv_usec < 0)
    do {
      delta_time.tv_usec += 1000000;
      --delta_time.tv_sec;
    } while (delta_time.tv_usec < 0);
  else
    while (delta_time.tv_usec >= 1000000) {
      delta_time.tv_usec -= 1000000;
      ++delta_time.tv_sec;
    }

  if (delta_time.tv_sec >= 0) {
    useconds = delta_time.tv_usec + 1000000 * delta_time.tv_sec;
    if (useconds > 0) {
      int result = usleep(useconds);
      if (result != 0) {
	perror("usleep Failed");
	return;
      }
    }
  }
}

void waitALittle()
{
  useconds_t useconds = 1000;
  int result = usleep(useconds);

  if (result != 0) {
    perror("usleep Failed");
    return;
  }
}

static void callback_handler(u_char *user __attribute__((unused)),
    const struct pcap_pkthdr *h,
    const u_char *bytes)
{
  unsigned int caplen = h->caplen;
  unsigned int len    = h->len;

  struct ether_header eth_hdr;
  struct ip ip_hdr;
  struct udphdr udp_hdr;

  uint16_t protocol;

  unsigned int ipLen;
  unsigned int dataLen;

  int result;
  ssize_t byteCount;

  struct timeval now_tod;
  struct timeval now_pcap;
  struct timeval actual_delta;

  char   s[12];
  char  *sResult;
  char  *endPtr;

  /*
   * No way to do something with truncated packet
   */
  if (caplen != len)
    return;

  /* Copy the ethernet header */
  if (len < sizeof(eth_hdr))
    return;
  memcpy(&eth_hdr, bytes, sizeof(eth_hdr));
  bytes += sizeof(eth_hdr);
  len   -= sizeof(eth_hdr);

  /* Discard non IP datagram */
  protocol = ntohs(eth_hdr.ether_type);
  if (protocol != ETHERTYPE_IP)
    return;

  /* Copy the IPv4 header */
  if (len < sizeof(ip_hdr))
    return;
  memcpy(&ip_hdr, bytes, sizeof(ip_hdr));
  ipLen = ip_hdr.ip_hl * 4;
  if (len < ipLen)
    return;
  bytes += ipLen;
  len   -= ipLen;

  /* Discard non UDP datagram */
  if (ip_hdr.ip_p != IPPROTO_UDP)
    return;

  /* Reject broadcast datagram */
  if (ip_hdr.ip_dst.s_addr == INADDR_BROADCAST)
    return;

  /* Copy the UDP header */
  if (len < sizeof(udp_hdr))
    return;
  memcpy(&udp_hdr, bytes, sizeof(udp_hdr));
  bytes += sizeof(udp_hdr);
  len   -= sizeof(udp_hdr);

  /* Discard uncomplete UDP datagram */
#ifdef HAVE_STRUCT_UDPHDR_UH_ULEN
  dataLen = ntohs(udp_hdr.uh_ulen) - sizeof(udp_hdr);
#else
  dataLen = ntohs(udp_hdr.len) - sizeof(udp_hdr);
#endif
  if (len < dataLen)
    return;

  if (flood) {
    waitALittle();
  } else if (oneByOne) {
    if (countToFlood > 0) {
      countToFlood--;
      waitALittle();
    } else {
      printf("Press <Enter> to send next datagram ->");
      sResult = fgets(s, sizeof(s), stdin);
      if (sResult == NULL)
	return;
      countToFlood = strtol(s, &endPtr, 0);
      if (endPtr == s)
	countToFlood = 0;
      if (countToFlood > 0)
	countToFlood--;
      else
	countToFlood = 0;
    }
  } else {
    /* Getting actual time and pcap time */
    result = gettimeofday(&now_tod, NULL);
    if (result != 0) {
      perror("Get Time of Day Failed");
      return;
    }
    now_pcap = h->ts;

    actual_delta.tv_sec  = now_pcap.tv_sec  - now_tod.tv_sec;
    actual_delta.tv_usec = now_pcap.tv_usec - now_tod.tv_usec;

    /* Wait, if necessary, following the interdatagram delay */
    waitBeforeSending(actual_delta);
  }

  /* Set destination */
  if (!dvalue)
    sockaddr.sin_addr.s_addr = ip_hdr.ip_dst.s_addr;
#ifdef HAVE_STRUCT_UDPHDR_UH_DPORT
  sockaddr.sin_port = udp_hdr.uh_dport;
#else
  sockaddr.sin_port = udp_hdr.dest;
#endif

  /* Send UDP data */
  byteCount = sendto(udpSocket, bytes, dataLen, 0,
      (struct sockaddr *)&sockaddr, sizeof(sockaddr));
  if (byteCount < 0) {
    perror("UDP sendto failed");
  }
}

void replayAll(pcap_t *pcap) {
  int result;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    perror("UDP Socket failed");
    return;
  }

  result = pcap_loop(pcap, -1, callback_handler, NULL);
  if (result == -1) {
    pcap_perror(pcap, "Error during pcap_loop\n");
  } else if (result == -2) {
    printf("pcap_breakloop() called before any packets were processed.\n");
  } else if (result != 0) {
    printf("Result (%d) from pcap_loop() not foreseen\n", result);
  }
}
