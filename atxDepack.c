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

static u_char fspec[49];

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

static unsigned int computeAsterix1Length(
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

  if (fspec[2]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[3]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
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

  if (fspec[6]) {
    dataLen -= 2;
    if (dataLen < 0)
      return currLen;
    bytes   += 2;
    currLen += 2;
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

  if (fspec[14]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  return currLen;
}

static unsigned int computeAsterix21Length(
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

  if (fspec[2]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen < 0)
      return currLen;
  }

  if (fspec[3]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[4]) {
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[5]) {
    bytes   += 6;
    dataLen -= 6;
    currLen += 6;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[6]) {
    bytes   += 8;
    dataLen -= 8;
    currLen += 8;
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
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[9]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[10]) {
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[11]) {
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
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
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
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
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[16]) {
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

  if (fspec[17]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
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
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
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
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
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
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[25]) {
    bytes   += 4;
    dataLen -= 4;
    currLen += 4;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[26]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[27]) {
    bytes   += 3;
    dataLen -= 3;
    currLen += 3;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[28]) {
    bytes   += 6;
    dataLen -= 6;
    currLen += 6;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[29]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[30]) {
    dataLen -= 1;
    if (dataLen <= 0)
      return currLen;
    int ws  = *bytes & 0x80;
    int wd  = *bytes & 0x40;
    int tmp = *bytes & 0x20;
    int trp = *bytes & 0x10;
    bytes   += 1;
    currLen += 1;
    if (ws)
    {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (wd)
    {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (tmp)
    {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (trp)
    {
      bytes   += 2;
      dataLen -= 2;
      currLen += 2;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[31]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[32]) {
    bytes   += 2;
    dataLen -= 2;
    currLen += 2;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[33]) {
    dataLen -= 1;
    if (dataLen <= 0)
      return currLen;
    int tis  = *bytes & 0x80;
    int tid  = *bytes & 0x40;
    bytes   += 1;
    currLen += 1;
    if (tis)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }
    if (tid)
    {
      if (dataLen <= 0)
        return currLen;
      int len = *bytes * 15 + 1;
      bytes   += len;
      dataLen -= len;
      currLen += len;
    }
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[34]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[35]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[36]) {
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
  }

  if (fspec[37]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[38]) {
    int rep = *bytes * 8 + 1;
    bytes   += rep;
    dataLen -= rep;
    currLen += rep;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[39]) {
    bytes   += 7;
    dataLen -= 7;
    currLen += 7;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[40]) {
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[41]) {
    int fx;
    int aos;
    int trd;
    int m3a;
    int qi;
    int ti;
    int mam;
    int gh;
    int fl  = 0;
    int sal = 0;
    int fsa = 0;
    int as  = 0;
    int tas = 0;
    int mh  = 0;
    int bvr = 0;
    int gvr = 0;
    int gv  = 0;
    int tar = 0;
    int tid = 0;
    int ts  = 0;
    int met = 0;
    int roa = 0;
    int ara = 0;
    int scc = 0;

    if (dataLen <= 0)
      return currLen;

    aos = *bytes & 0x80;
    trd = *bytes & 0x40;
    m3a = *bytes & 0x20;
    qi  = *bytes & 0x10;
    ti  = *bytes & 0x08;
    mam = *bytes & 0x04;
    gh  = *bytes & 0x02;
    fx  = *bytes & 0x01;
    bytes   += 1;
    dataLen -= 1;
    currLen += 1;

    if (fx)
    {
      if (dataLen <= 0)
        return currLen;

      fl  = *bytes & 0x80;
      sal = *bytes & 0x40;
      fsa = *bytes & 0x20;
      as  = *bytes & 0x10;
      tas = *bytes & 0x08;
      mh  = *bytes & 0x04;
      bvr = *bytes & 0x02;
      fx  = *bytes & 0x01;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (fx)
    {
      if (dataLen <= 0)
        return currLen;

      gvr = *bytes & 0x80;
      gv  = *bytes & 0x40;
      tar = *bytes & 0x20;
      tid = *bytes & 0x10;
      ts  = *bytes & 0x08;
      met = *bytes & 0x04;
      roa = *bytes & 0x02;
      fx  = *bytes & 0x01;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (fx)
    {
      if (dataLen <= 0)
        return currLen;

      ara = *bytes & 0x80;
      scc = *bytes & 0x40;
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (aos)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (trd)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (m3a)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (qi)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (ti)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (mam)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (gh)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (fl)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (sal)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (fsa)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (as)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (tas)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (mh)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (bvr)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (gvr)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (gv)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (tar)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (tid)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (ts)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (met)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (roa)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (ara)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (scc)
    {
      bytes   += 1;
      dataLen -= 1;
      currLen += 1;
    }

    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[47]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
    if (dataLen <= 0)
      return currLen;
  }

  if (fspec[48]) {
    int len = *bytes;
    bytes   += len;
    dataLen -= len;
    currLen += len;
  }
  return currLen;
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
    case 1:
      currLen += computeAsterix1Length(bytes, len);
      break;
    case 21:
      currLen += computeAsterix21Length(bytes, len);
      break;
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

static void write_dump_eth(u_char *pcapOutput, const struct pcap_pkthdr *h,
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

static void write_dump_sll(u_char *pcapOutput, const struct pcap_pkthdr *h,
    const struct sll_header *sll_hdr, const struct ip *ip_hdr,
    const struct udphdr *udp_hdr, int category, const u_char *pos,
    unsigned int currLen)
{
  struct pcap_pkthdr new_h;
  struct sll_header  new_sll_hdr;
  char               ipRaw[60];
  struct udphdr      new_udp_hdr;

  unsigned int asterixLength = currLen + 3;
  unsigned int udpLength     = asterixLength + sizeof(udp_hdr);
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
      if (datalink == DLT_LINUX_SLL)
        write_dump_sll((u_char *)pcapOutput, h, &sll_hdr, &ip_hdr, &udp_hdr,
            category, pos, currLen);
      else
        write_dump_eth((u_char *)pcapOutput, h, &eth_hdr, &ip_hdr, &udp_hdr,
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
