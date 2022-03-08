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

#include <getopt.h>
#include <stdlib.h>

static pcap_dumper_t *pcapOutput;

static u_char fspec[28];

static unsigned int computeFSPEC(
    const u_char *bytes,
    unsigned int  dataLen)
{
  memset(fspec, 0, sizeof(fspec));
  unsigned int i = 0;
  unsigned int j = 0;
  for (; i < dataLen; i++)
  {
    u_char fspec_byte = bytes[i];
    fspec[j++] = fspec_byte & 0x80;
    fspec[j++] = fspec_byte & 0x40;
    fspec[j++] = fspec_byte & 0x20;
    fspec[j++] = fspec_byte & 0x10;
    fspec[j++] = fspec_byte & 0x08;
    fspec[j++] = fspec_byte & 0x04;
    fspec[j++] = fspec_byte & 0x02;
    if (!(fspec_byte & 0x01))
      break;
  }
  return i + 1;
}

static unsigned int computeAsterix34Length(
    const u_char *bytes,
    unsigned int  dataLen)
{
  unsigned int currLen = 0;

  if (fspec[0]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[1]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[2]) {
    dataLen -= 3;
    if (dataLen < 0)
      return currLen;
    bytes   += 3;
    currLen += 3;
  }
  if (dataLen <= 0)
    return currLen;

  if (fspec[3]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[4]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[5]) {
    dataLen -= 1;
    if (dataLen <= 0)
      return currLen;
    int com = *bytes & 0x80;
    int psr = *bytes & 0x10;
    int ssr = *bytes & 0x08;
    int mds = *bytes & 0x04;
    bytes   += 1;
    currLen += 1;
    if (com) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (psr) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (ssr) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (mds) {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[6]) {
    dataLen -= 1;
    if (dataLen <= 0)
      return currLen;
    int com = *bytes & 0x80;
    int psr = *bytes & 0x10;
    int ssr = *bytes & 0x08;
    int mds = *bytes & 0x04;
    bytes   += 1;
    currLen += 1;
    if (com) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (psr) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (ssr) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (mds) {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[7]) {
    dataLen -= 1;
    if (dataLen <= 0)
      return currLen;
    int rep = *bytes;
    bytes   += 1;
    currLen += 1;
    bytes   += rep * 2;
    dataLen -= rep * 2;
    currLen += rep * 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[8]) {
    bytes   += 8;
    dataLen -= 8;
    currLen += 8;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[9]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[10]) {
    bytes   += 8;
    dataLen -= 8;
    currLen += 8;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[11]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[12]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[13]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
  }
  return currLen;
}

static unsigned int computeAsterix48Length(
    const u_char *bytes,
    unsigned int  dataLen)
{
  unsigned int currLen = 0;

  if (fspec[0]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[1]) {
    dataLen -= 3;
    if (dataLen < 0)
      return currLen;
    bytes   += 3;
    currLen += 3;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[2]) {
    while (1) {
      if (dataLen <= 0)
        return currLen;
      int cont = *bytes & 0x01;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
      if (!cont)
        break;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[3]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[4]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[5]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[6]) {
    int srl = *bytes & 0x80;
    int srr = *bytes & 0x40;
    int sam = *bytes & 0x20;
    int prl = *bytes & 0x10;
    int pam = *bytes & 0x08;
    int rpd = *bytes & 0x04;
    int apd = *bytes & 0x02;
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (srl)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (srr)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (sam)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (prl)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
      if (pam)
      {
        bytes   += 1;
        dataLen -= 1;
        currLen += 1;
      }
      if (rpd)
      {
        bytes   += 1;
        dataLen -= 1;
        currLen += 1;
      }
      if (apd)
      {
        bytes   += 1;
        dataLen -= 1;
        currLen += 1;
      }
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[7]) {
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[8]) {
    bytes   += 6;
    dataLen -= 6;
    currLen += 6;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[9]) {
    int rep = *bytes;
    bytes   += 1 + 8 * rep;
    dataLen -= 1 + 8 * rep;
    currLen += 1 + 8 * rep;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[10]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[11]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[12]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[13]) {
    while (1) {
      if (dataLen <= 0)
        return currLen;
      int cont = *bytes & 0x01;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
      if (!cont)
        break;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[14]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[15]) {
    while (1) {
      if (dataLen <= 0)
        return currLen;
      int cont = *bytes & 0x01;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
      if (!cont)
        break;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[16]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[17]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[18]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[19]) {
    int cal = *bytes & 0x80;
    int rds = *bytes & 0x40;
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (cal)
    {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (rds)
    {
      if (dataLen <= 0)
        return currLen;
      int rep = *bytes;
      bytes   += 1 + 6 * rep;
      dataLen -= 1 + 6 * rep;
      currLen += 1 + 6 * rep;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[20]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[21]) {
    bytes   += 7;
    dataLen -= 7;
    currLen += 7;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[22]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[23]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[24]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[25]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[26]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[27]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
    if (dataLen <= 0)
      return currLen;
  }

  return currLen;
}

static unsigned int computeDataRecordLength(
    const u_char *bytes,
    unsigned int  category,
    unsigned int  len)
{
  unsigned int currLen;
  unsigned int fspec_len = computeFSPEC(bytes, len);

  bytes  += fspec_len;
  len    -= fspec_len;
  currLen = fspec_len;

  if (len <= 0)
    return currLen;

  switch (category)
  {
    case 34:
      currLen += computeAsterix34Length(bytes, len);
      break;
    case 48:
      currLen += computeAsterix48Length(bytes, len);
      break;
    default:
      currLen += len;
      break;
  }
  return currLen;
}

static int isAsterix(
    const u_char *bytes,
    unsigned int dataLen)
{
  unsigned int remainingData = dataLen;
  while (remainingData > 3)
  {
    unsigned int currLength = bytes[1] * 256 + bytes[2];
    if (currLength <= 3)
      break;
    remainingData -= currLength;
    bytes         += currLength;
  }
  return remainingData == 0;
}

static void write_dump(u_char *pcapOutput, const struct pcap_pkthdr *h,
    const struct ether_header *eth_hdr, const struct ip *ip_hdr,
    const struct udphdr *udp_hdr, int category, const u_char *pos,
    unsigned int currLen)
{
  struct pcap_pkthdr  new_h;
  struct ether_header new_eth_hdr;
  char                ipRaw[60];
  struct udphdr       new_udp_hdr;

  unsigned int asterixLength = currLen + 3;
  unsigned int udpLength     = asterixLength + sizeof(udp_hdr);
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

  *temp++ = category;

  *temp++ = asterixLength / 256;
  *temp++ = asterixLength % 256;

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
  struct ip ip_hdr;
  struct udphdr udp_hdr;
  struct vlan_tag vlan_hdr;

  uint16_t protocol;

  unsigned int ipLen;
  unsigned int dataLen;

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

  if (!isAsterix(bytes, dataLen))
  {
    pcap_dump((u_char *)pcapOutput, h, save_bytes);
    return;
  }

  const u_char *pos = bytes;
  while (dataLen > 0)
  {
    unsigned int category;
    unsigned int len;
    unsigned int currLen;
    unsigned int remaining;

    category = *pos++;
    len      = *pos++;
    len     *= 256;
    len     += *pos++;

    remaining = len - 3;

    while (remaining > 0)
    {
      currLen    = computeDataRecordLength(pos, category, remaining);
      write_dump((u_char *)pcapOutput, h, &eth_hdr, &ip_hdr, &udp_hdr,
          category, pos, currLen);
      remaining -= currLen;
      pos       += currLen;
    }

    pos     += len;
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
