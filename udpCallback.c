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

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pcap/vlan.h>

#include "asterix.h"

static int start_loop = 1;
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

void waitALittle(ReplayCtx *ctx)
{
  int result = usleep(ctx->floodTime);

  if (result != 0) {
    perror("usleep Failed");
    return;
  }
}

int waitToLoop(ReplayCtx *ctx)
{
  int result = usleep(ctx->loopTime);

  if (result != 0) {
    perror("usleep Failed");
  }

  return result;
}

static void callback_handler(u_char *user,
    const struct pcap_pkthdr *h,
    const u_char *bytes)
{
  ReplayCtx *ctx = (ReplayCtx *)user;

  unsigned int caplen = h->caplen;
  unsigned int len    = h->len;

  struct ether_header eth_hdr;
  struct ip ip_hdr;
  struct udphdr udp_hdr;
  struct vlan_tag vlan_hdr;

  uint16_t protocol;

  unsigned int ipLen;
  unsigned int dataLen;

  ssize_t byteCount;


  char   s[12];
  char  *sResult;
  char  *endPtr;

  /*
   * No way to do something with truncated packet
   */
  if (caplen != len)
    return;

  if (ctx->datalink == DLT_EN10MB) {
    /* Copy the ethernet header */
    if (len < sizeof(eth_hdr))
      return;
    memcpy(&eth_hdr, bytes, sizeof(eth_hdr));
    bytes += sizeof(eth_hdr);
    len   -= sizeof(eth_hdr);

    protocol = ntohs(eth_hdr.ether_type);

    /* Check for VLAN data */
    if (protocol == ETHERTYPE_VLAN)
    {
      /* Copy the vlan header */
      if (len < sizeof(vlan_hdr))
        return;
      memcpy(&vlan_hdr, bytes, sizeof(vlan_hdr));
      bytes += sizeof(vlan_hdr);
      len   -= sizeof(vlan_hdr);

      protocol = ntohs(vlan_hdr.vlan_tci);
    }

    /* Discard non IP datagram */
    if (protocol != ETHERTYPE_IP)
      return;
  }

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

  /* 2. High-Resolution Timing Logic */
  if (ctx->flood) {
    waitALittle(ctx);
  } else if (ctx->oneByOne) {
    if (countToFlood > 0) {
      countToFlood--;
      waitALittle(ctx);
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
    struct timespec deadline;

    // Initialize start times on the first packet
    if (start_loop) {
      start_loop = 0;
      ctx->start_pcap.tv_sec = h->ts.tv_sec;
      ctx->start_pcap.tv_nsec = h->ts.tv_usec * 1000;
      clock_gettime(CLOCK_MONOTONIC, &ctx->start_wall);
    } else {
      // Calculate the offset of this packet from the start of the PCAP
      long diff_sec = h->ts.tv_sec - ctx->start_pcap.tv_sec;
      long diff_nsec = (h->ts.tv_usec * 1000) - ctx->start_pcap.tv_nsec;

      // Calculate absolute deadline: start_wall + pcap_offset
      deadline.tv_sec = ctx->start_wall.tv_sec + diff_sec;
      deadline.tv_nsec = ctx->start_wall.tv_nsec + diff_nsec;

      // Normalize nanoseconds
      if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
      } else if (deadline.tv_nsec < 0) {
        deadline.tv_sec--;
        deadline.tv_nsec += 1000000000L;
      }

      // Sleep until the exact nanosecond deadline
      // TIMER_ABSTIME ensures we don't drift even if processing takes time
      clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    }
  }

  /* Set destination */
  if (!ctx->dvalue)
    ctx->sockaddr.sin_addr.s_addr = ip_hdr.ip_dst.s_addr;
  if (!ctx->pvalue) {
#ifdef HAVE_STRUCT_UDPHDR_UH_DPORT
    ctx->sockaddr.sin_port = udp_hdr.uh_dport;
#else
    ctx->sockaddr.sin_port = udp_hdr.dest;
#endif
  }

  if (ctx->asterixTime)
  {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    unsigned int tod = (now.tv_sec % 86400) * 128
      + (now.tv_nsec * 128 / 1000000000L);
    bytes = fixAsterixTOD(bytes, dataLen, tod);
  }

  /* Send UDP data */
  byteCount = sendto(ctx->udpSocket, bytes, dataLen, 0,
      (struct sockaddr *)&ctx->sockaddr, sizeof(ctx->sockaddr));
  if (byteCount < 0) {
    perror("UDP sendto failed");
  }
}

void replayAll(pcap_t *pcap, ReplayCtx *ctx) {
  int result;

  ctx->udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (ctx->udpSocket == -1) {
    perror("UDP Socket failed");
    return;
  }
  if (ctx->setMulticastTTL) {
    u_char ttl = ctx->multicastTTLValue;
    setsockopt(ctx->udpSocket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  }
  if (ctx->setBroadcast) {
    int brd = 1;
    setsockopt(ctx->udpSocket, SOL_SOCKET, SO_BROADCAST, &brd, sizeof(brd));
  }
  result = pcap_loop(pcap, -1, callback_handler, (u_char *)ctx);
  if (result == -1) {
    pcap_perror(pcap, "Error during pcap_loop\n");
  } else if (result == -2) {
    printf("pcap_breakloop() called before any packets were processed.\n");
  } else if (result != 0) {
    printf("Result (%d) from pcap_loop() not foreseen\n", result);
  }

  close(ctx->udpSocket);
  ctx->udpSocket = -1;
}

// Local Variables: ***
// mode: C ***
// tab-width: 2 ***
// c-basic-offset: 2 ***
// indent-tabs-mode: nil ***
// End: ***
// ex: shiftwidth=2 tabstop=2
