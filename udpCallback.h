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

#include <pcap/pcap.h>

extern struct sockaddr_in sockaddr;
extern int rewriteDestination;
extern char *dvalue;
extern char *pvalue;
extern int flood;
extern int oneByOne;
extern int asterixTime;
extern int  setMulticastTTL;
extern long multicastTTLValue;

extern void replayAll(pcap_t *pcap);
