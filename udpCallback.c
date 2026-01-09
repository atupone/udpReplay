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
#include <errno.h>

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

static void flush_batch(ReplayCtx *ctx) {
  if (ctx->msg_count == 0) return;

  // Send the entire batch in ONE system call
  int retval = sendmmsg(ctx->udpSocket, ctx->msgs, ctx->msg_count, 0);

  if (retval < 0) {
    // ENOBUFS means the kernel's transmit queue is full
    if (errno == ENOBUFS) {
      nsleep(100); // Wait 100us for the queue to drain and try again or just drop
    } else {
      perror("sendmmsg failed");
    }
  }

  // Clear the count immediately
  ctx->msg_count = 0; // Reset for next batch

  // Throttle: Put the delay INSIDE the flush logic
  // This protects the NIC from being overwhelmed by back-to-back batches
  if (ctx->flood && ctx->floodTime > 0) {
    nsleep(ctx->floodTime);
  }
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

  /* Basic Validation */
  if (ip_hdr->ip_v != 4) return; // Ensure it's actually IPv4

  /* Discard non UDP datagram */
  if (ip_hdr->ip_p != IPPROTO_UDP) return;

  /* Reject broadcast datagram */
  if ((ip_hdr->ip_dst.s_addr == INADDR_BROADCAST) && !ctx->setBroadcast) return;

  /* Calculate and Validate IP Header Length (including Options) */
  uint32_t ipLen = ip_hdr->ip_hl * 4;

  // Must be at least the size of the standard struct
  if (ipLen < sizeof(struct ip)) return;

  // Must fit within the captured pcap data
  if (remaining < ipLen) return;

  /* Advance past IP Header (and any options) */
  data_ptr  += ipLen;
  remaining -= ipLen;

  /* Layer 4 Parsing (UDP) */
  REQUIRE_BYTES(sizeof(struct udphdr));
  struct udphdr *udp_hdr = (struct udphdr *)data_ptr;

#ifdef HAVE_STRUCT_UDPHDR_UH_ULEN
  uint32_t udp_total_len = ntohs(udp_hdr->uh_ulen);
#else
  uint32_t udp_total_len = ntohs(udp_hdr->len);
#endif

  // The total length includes the 8-byte UDP header
  if (udp_total_len < sizeof(struct udphdr)) return;
  uint32_t dataLen = udp_total_len - sizeof(struct udphdr);

  data_ptr  += sizeof(struct udphdr);
  remaining -= sizeof(struct udphdr);

  /* Final data sanity check */
  if (remaining < dataLen) return;

  /* 2. High-Resolution Timing Logic */
  if (ctx->flood) {
    // --- BATCH SENDING LOGIC ---
    int i = ctx->msg_count;

    // 1. Copy payload to the batch buffer
    memcpy(ctx->buffers[i], data_ptr, dataLen);

    // 2. Set up the iovec and mmsghdr for this packet
    ctx->iovecs[i].iov_base = ctx->buffers[i];
    ctx->iovecs[i].iov_len  = dataLen;
    ctx->msgs[i].msg_hdr.msg_iov = &ctx->iovecs[i];
    ctx->msgs[i].msg_hdr.msg_iovlen = 1;
    ctx->msgs[i].msg_hdr.msg_name = &ctx->sockaddr;
    ctx->msgs[i].msg_hdr.msg_namelen = sizeof(ctx->sockaddr);

    ctx->msg_count++;

    // 3. If batch is full, send it
    if (ctx->msg_count == VLEN) {
      flush_batch(ctx);
    }
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
    struct timespec now;

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

      // Hybrid Delay: Sleep then Spin
      clock_gettime(CLOCK_MONOTONIC, &now);

      // Calculate remaining nanoseconds
      long remaining_ns = (deadline.tv_sec - now.tv_sec) * 1000000000L +
                          (deadline.tv_nsec - now.tv_nsec);

      // Threshold: 200 microseconds (200,000 ns)
      // If we have plenty of time, sleep to be nice to the OS
      if (remaining_ns > 200000) {
        struct timespec sleep_until = deadline;
        // Adjust sleep_until to wake up slightly BEFORE the deadline
        sleep_until.tv_nsec -= 100000;
        if (sleep_until.tv_nsec < 0) {
          sleep_until.tv_sec--;
          sleep_until.tv_nsec += 1000000000L;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &sleep_until, NULL);
      }

      // Busy-Wait (Spin) for the final precision
      do {
        clock_gettime(CLOCK_MONOTONIC, &now);
      } while (now.tv_sec < deadline.tv_sec ||
              (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
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
    fixAsterixTOD(asterix_buf, dataLen, tod);
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

  ctx->msg_count = 0; // Initialize batch counter
                      //
  int result = pcap_loop(pcap, -1, callback_handler, (u_char *)ctx);

  if (result == -1) {
    pcap_perror(pcap, "Error during pcap_loop\n");
  } else if (result == -2) {
    printf("pcap_breakloop() called before any packets were processed.\n");
  } else if (result != 0) {
    printf("Result (%d) from pcap_loop() not foreseen\n", result);
  }

  // FINAL FLUSH: Send remaining packets that didn't fill a full batch
  if (ctx->flood) {
    flush_batch(ctx);
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
