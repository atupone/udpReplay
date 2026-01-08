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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/vlan.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>

#include <getopt.h>
#include <stdlib.h>

static pcap_dumper_t *pcapOutput;
int                   datalink;

static int isLiu(
    const u_char *bytes,
    unsigned int dataLen)
{
  unsigned int remainingData = dataLen;
  while (remainingData >= 6)
  {
    unsigned int currLength = bytes[0] * 256 + bytes[1];
    if (currLength <= 3)
      break;
    remainingData -= currLength;
    bytes         += currLength;
  }
  return remainingData == 0;
}

static void write_dump_eth(u_char *pcapOutput, const struct pcap_pkthdr *h,
    const struct ether_header *eth_hdr, const struct ip *ip_hdr,
    const struct udphdr *udp_hdr, const u_char *pos,
    unsigned int currLen)
{
  struct pcap_pkthdr  new_h;
  struct ether_header new_eth_hdr;
  char                ipRaw[60];
  struct udphdr       new_udp_hdr;

  unsigned int udpLength     = currLen + sizeof(udp_hdr);
  unsigned int ipLen         = ip_hdr->ip_hl * 4;
  unsigned int ipLength      = udpLength + ipLen;

  memcpy(&new_h, h, sizeof(new_h));
  new_h.caplen = sizeof(struct ether_header) + ipLength;
  new_h.len    = new_h.caplen;

  u_char bytes[65536];

  u_char *temp = bytes;

  memcpy(&new_eth_hdr, eth_hdr, sizeof(struct ether_header));
  new_eth_hdr.ether_type = htons(ETHERTYPE_IP);

  memcpy(temp, &new_eth_hdr, sizeof(struct ether_header));
  temp += sizeof(struct ether_header);

  ipLen = ip_hdr->ip_hl * 4;
  memcpy(ipRaw, ip_hdr, ipLen);
  ((struct ip *)ipRaw)->ip_len = htons(ipLength);

  memcpy(temp, ipRaw, ipLen);
  temp += ipLen;

  memcpy(&new_udp_hdr, udp_hdr, sizeof(struct udphdr));
  new_udp_hdr.len = htons(udpLength);

  memcpy(temp, &new_udp_hdr, sizeof(struct udphdr));
  temp += sizeof(struct udphdr);

  memcpy(temp, pos, currLen);

  pcap_dump(pcapOutput, &new_h, bytes);
}

static void write_dump_sll(u_char *pcapOutput, const struct pcap_pkthdr *h,
    const struct sll_header *sll_hdr, const struct ip *ip_hdr,
    const struct udphdr *udp_hdr, const u_char *pos,
    unsigned int currLen)
{
  struct pcap_pkthdr new_h;
  struct sll_header  new_sll_hdr;
  char               ipRaw[60];
  struct udphdr      new_udp_hdr;

  unsigned int udpLength     = currLen + sizeof(udp_hdr);
  unsigned int ipLen         = ip_hdr->ip_hl * 4;
  unsigned int ipLength      = udpLength + ipLen;

  memcpy(&new_h, h, sizeof(new_h));
  new_h.caplen = sizeof(struct sll_header) + ipLength;
  new_h.len    = new_h.caplen;

  u_char bytes[65536];

  u_char *temp = bytes;

  memcpy(&new_sll_hdr, sll_hdr, sizeof(struct sll_header));
  new_sll_hdr.sll_protocol = htons(ETHERTYPE_IP);

  memcpy(temp, &new_sll_hdr, sizeof(struct sll_header));
  temp += sizeof(struct sll_header);

  ipLen = ip_hdr->ip_hl * 4;
  memcpy(ipRaw, ip_hdr, ipLen);
  ((struct ip *)ipRaw)->ip_len = htons(ipLength);

  memcpy(temp, ipRaw, ipLen);
  temp += ipLen;

  memcpy(&new_udp_hdr, udp_hdr, sizeof(struct udphdr));
  new_udp_hdr.len = htons(udpLength);

  memcpy(temp, &new_udp_hdr, sizeof(struct udphdr));
  temp += sizeof(struct udphdr);

  memcpy(temp, pos, currLen);

  pcap_dump(pcapOutput, &new_h, bytes);
}

static void callback_handler(u_char *user __attribute__((unused)),
    const struct pcap_pkthdr *h,
    const u_char *bytes)
{
  const u_char *save_bytes = bytes;

  unsigned int caplen = h->caplen;
  unsigned int len    = h->len;

  struct ether_header eth_hdr;
  struct sll_header   sll_hdr;
  struct ip ip_hdr;
  struct udphdr udp_hdr;
  struct vlan_tag vlan_hdr;

  uint16_t protocol;

  unsigned int ipLen;
  unsigned int dataLen;

  /*
   * No way to do something with truncated packet
   */
  if (caplen < len)
    return;

  if (datalink == DLT_LINUX_SLL)
  {
    /* Copy the sll header */
    if (len < sizeof(sll_hdr))
      return;

    memcpy(&sll_hdr, bytes, sizeof(sll_hdr));
    bytes += sizeof(sll_hdr);
    len   -= sizeof(sll_hdr);

    protocol = ntohs(sll_hdr.sll_protocol);
  }
  else if (datalink == DLT_EN10MB)
  {
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
  }
  else
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
    return;
  }

  /* Discard non IP datagram */
  if (protocol != ETHERTYPE_IP)
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
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
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
    return;
  }

  /* Reject broadcast datagram */
  if (ip_hdr.ip_dst.s_addr == INADDR_BROADCAST)
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
    return;
  }

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

  if (!isLiu(bytes, dataLen))
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
    return;
  }

  const u_char *pos = bytes;
  while (dataLen > 0)
  {
    unsigned int len;
    unsigned int remaining;

    len  = *pos++;
    len *= 256;
    len += *pos++;
    pos += 4;

    remaining = len - 6;

    if (datalink == DLT_LINUX_SLL)
      write_dump_sll((u_char *)pcapOutput, h, &sll_hdr, &ip_hdr, &udp_hdr,
        pos, remaining);
    else
      write_dump_eth((u_char *)pcapOutput, h, &eth_hdr, &ip_hdr, &udp_hdr,
        pos, remaining);

    pos     += remaining;
    dataLen -= len;
  }
}

int main(int argc, char* argv[])
{
  const char    *pcapNameInput;
  char           errbuf[PCAP_ERRBUF_SIZE];
  pcap_t        *pcapInput;
  int            result;

  if (argc != 2) {
    printf("Need exactly a parameter: name of pcap file\n");
    return -1;
  }

  pcapNameInput  = argv[1];

  pcapInput = pcap_open_offline(pcapNameInput, errbuf);

  if (pcapInput == NULL) {
    printf("Open of pcap file [%s] failed: %s\n", pcapNameInput, errbuf);
    return -1;
  }

  datalink = pcap_datalink(pcapInput);
  if (datalink == PCAP_ERROR_NOT_ACTIVATED) {
    printf("capfile not activated\n");
    return -1;
  }

  if (datalink == DLT_LINUX_SLL)
    ;
  else if (datalink == DLT_EN10MB)
    ;
  else
    printf("Data Link Type unprocessed: %i\n", datalink);

  pcapOutput = pcap_dump_open(pcapInput, "-");
  if (pcapOutput == NULL) {
    printf("Open of dump file failed: %s\n", errbuf);
    return -1;
  }

  result = pcap_loop(pcapInput, -1, callback_handler, NULL);
  if (result == -1) {
    pcap_perror(pcapInput, "Error during pcap_loop\n");
  } else if (result == -2) {
    printf("pcap_breakloop() called before any packets were processed.\n");
  } else if (result != 0) {
    printf("Result (%d) from pcap_loop() not foreseen\n", result);
  }

  return 0;
}

// Local Variables: ***
// mode: C ***
// tab-width: 2 ***
// c-basic-offset: 2 ***
// indent-tabs-mode: nil ***
// End: ***
// ex: shiftwidth=2 tabstop=2
