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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pcap/vlan.h>

#include "asterix.h"

// Helper to replace deprecated usleep
static void nsleep(long usec) {
  struct timespec ts;
  ts.tv_sec = usec / 1000000;
  ts.tv_nsec = (usec % 1000000) * 1000;
  nanosleep(&ts, NULL);
}

static int start_loop = 1;
long int countToFlood = 0;

int waitToLoop(ReplayCtx *ctx)
{
  nsleep(ctx->loopTime);

  return 0;
}

static void callback_handler(u_char *user,
    const struct pcap_pkthdr *h,
    const u_char *bytes)
{
  ReplayCtx *ctx = (ReplayCtx *)user;
  const u_char *data_ptr = bytes;
  uint32_t remaining = h->caplen;

  /* Safety: No way to do something with truncated packet */
  if (h->caplen != h->len) return;

  /* Macro for bounds checking before pointer arithmetic */
  #define REQUIRE_BYTES(n) if (remaining < (n)) return

  /* Layer 2 Parsing & EtherType Check */
  uint16_t protocol = 0;
  if (ctx->datalink == DLT_EN10MB) {
    REQUIRE_BYTES(sizeof(struct ether_header));

    struct ether_header *eth_hdr = (struct ether_header *)data_ptr;
    protocol = ntohs(eth_hdr->ether_type);

    data_ptr  += sizeof(struct ether_header);
    remaining -= sizeof(struct ether_header);

    /* Handle VLAN tagging */
    if (protocol == ETHERTYPE_VLAN) {
      REQUIRE_BYTES(sizeof(struct ether_header));
      struct vlan_tag *vlan_hdr = (struct vlan_tag*)data_ptr;
      protocol = ntohs(vlan_hdr->vlan_tci);
      data_ptr  += sizeof(struct vlan_tag);
      remaining -= sizeof(struct vlan_tag);
    }

    /* Strict check to ensure we only process IPv4 */
    if (protocol != ETHERTYPE_IP) return;
  }

  // --- Layer 3 Parsing (IPv4) ---
  REQUIRE_BYTES(sizeof(struct ip));
  struct ip *ip_hdr = (struct ip *)data_ptr;

  /* Discard non UDP datagram */
  if (ip_hdr->ip_p != IPPROTO_UDP) return;

  /* Reject broadcast datagram */
  if ((ip_hdr->ip_dst.s_addr == INADDR_BROADCAST) && !ctx->setBroadcast) return;

  uint32_t ipLen = ip_hdr->ip_hl * 4;
  REQUIRE_BYTES(ipLen);
  data_ptr  += ipLen;
  remaining -= ipLen;

  /* Layer 4 Parsing (UDP) */
  REQUIRE_BYTES(sizeof(struct udphdr));
  struct udphdr *udp_hdr = (struct udphdr *)data_ptr;

#ifdef HAVE_STRUCT_UDPHDR_UH_ULEN
  uint32_t dataLen = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
#else
  uint32_t dataLen = ntohs(udp_hdr->len) - sizeof(struct udphdr);
#endif

  data_ptr  += sizeof(struct udphdr);
  remaining -= sizeof(struct udphdr);

  /* Final data sanity check */
  if (remaining < dataLen) return;

  /* 2. High-Resolution Timing Logic */
  if (ctx->flood) {
    nsleep(ctx->floodTime);
  } else if (ctx->oneByOne) {
    if (countToFlood > 0) {
      countToFlood--;
      nsleep(ctx->floodTime);
    } else {
      char   s[12];
      char  *sResult;
      char  *endPtr;

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

  // --- Prepare Destination ---
  if (!ctx->dvalue)
    ctx->sockaddr.sin_addr.s_addr = ip_hdr->ip_dst.s_addr;

  if (!ctx->pvalue) {
#ifdef HAVE_STRUCT_UDPHDR_UH_DPORT
    ctx->sockaddr.sin_port = udp_hdr->uh_dport;
#else
    ctx->sockaddr.sin_port = udp_hdr->dest;
#endif
  }

  // --- Asterix Modification (Optional) ---
  const u_char *send_ptr = data_ptr;
  u_char asterix_buf[65535];

  if (ctx->asterixTime && dataLen <= 65535) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    unsigned int tod = (now.tv_sec % 86400) * 128
      + (now.tv_nsec * 128 / 1000000000L);

    memcpy(asterix_buf, data_ptr, dataLen);
    // Cast away const for payload modification if necessary, or modify fixAsterixTOD signature
    fixAsterixTOD(data_ptr, dataLen, tod);
    send_ptr = asterix_buf;
  }

  // --- Send ---
  if (sendto(ctx->udpSocket, send_ptr, dataLen, 0,
             (struct sockaddr *)&ctx->sockaddr, sizeof(ctx->sockaddr)) < 0) {
    // Use errno to print clearer error (e.g., Network Unreachable)
    perror("UDP sendto failed");
  }
}

void replayAll(pcap_t *pcap, ReplayCtx *ctx) {
  // Reset loop state variable
  start_loop = 1;

  ctx->udpSocket = socket(AF_INET, SOCK_DGRAM, 0);

  if (ctx->udpSocket == -1) {
    perror("UDP Socket failed");
    return;
  }

  /* Set Socket Options */
  if (ctx->setMulticastTTL) {
    u_char ttl = ctx->multicastTTLValue;
    setsockopt(ctx->udpSocket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  }

  if (ctx->setBroadcast) {
    int brd = 1;
    setsockopt(ctx->udpSocket, SOL_SOCKET, SO_BROADCAST, &brd, sizeof(brd));
  }

  int result = pcap_loop(pcap, -1, callback_handler, (u_char *)ctx);

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
