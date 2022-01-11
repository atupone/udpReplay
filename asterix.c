#include "asterix.h"

#include <string.h>
#include <pcap/pcap.h>

static u_char fspec[28];

unsigned int computeFSPEC(
    u_char *bytes,
    unsigned int dataLen)
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

void setTOD(
    u_char *bytes,
    unsigned int tod)
{
  bytes[2] = tod & 0xff;
  tod >>= 8;
  bytes[1] = tod & 0xff;
  tod >>= 8;
  bytes[0] = tod;
}

unsigned int fixAsterix34TOD(
    u_char *bytes,
    unsigned int dataLen,
    unsigned int tod)
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
    setTOD(bytes, tod);
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

unsigned int fixAsterix48TOD(
    u_char *bytes,
    unsigned int dataLen,
    unsigned int tod)
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
    setTOD(bytes, tod);
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

int isAsterix(
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

unsigned int fixAsterixDataRecordTOD(
    u_char      *bytes,
    unsigned int category,
    unsigned int len,
    unsigned int tod)
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
      currLen += fixAsterix34TOD(bytes, len, tod);
      break;
    case 48:
      currLen += fixAsterix48TOD(bytes, len, tod);
      break;
    default:
      currLen += len;
      break;
  }
  return currLen;
}

unsigned int fixAsterixDataBlockTOD(
    u_char      *bytes,
    unsigned int tod)
{
  unsigned int category;
  unsigned int len;
  unsigned int currLen;
  unsigned int remaining;

  category = *bytes++;
  len      = *bytes++;
  len     *= 256;
  len     += *bytes++;

  remaining = len - 3;

  while (remaining > 0)
  {
    currLen    = fixAsterixDataRecordTOD(bytes, category, remaining, tod);
    remaining -= currLen;
    bytes     += currLen;
  }

  return len;
}

const u_char *fixAsterixTOD(
    const u_char *bytes,
    unsigned int dataLen,
    unsigned int tod)
{
  if (!isAsterix(bytes, dataLen))
    return bytes;

  static u_char newBytes[65536];
  memcpy(newBytes, bytes, dataLen);

  u_char *pos = newBytes;
  while (dataLen > 0)
  {
    unsigned int len = fixAsterixDataBlockTOD(pos, tod);
    pos     += len;
    dataLen -= len;
  }

  return newBytes;
}

// Local Variables: ***
// mode: C ***
// tab-width: 2 ***
// c-basic-offset: 2 ***
// indent-tabs-mode: nil ***
// End: ***
// ex: shiftwidth=2 tabstop=2
