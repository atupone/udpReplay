/*
 * Copyright (C) 2016 Alfredo Tupone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap/pcap.h>
#include <unistd.h>

typedef struct {
    int udpSocket;
    struct sockaddr_in sockaddr;
    char *dvalue;
    char *pvalue;
    int flood;
    useconds_t floodTime;
    int asterixTime;
    int setMulticastTTL;
    long multicastTTLValue;
    int setBroadcast;
    int datalink;
    int oneByOne;
    int loop;
    useconds_t loopTime;
} ReplayCtx;

extern void replayAll(pcap_t *pcap, ReplayCtx *ctx);
extern int waitToLoop(ReplayCtx *ctx);


// Local Variables: ***
// mode: C++ ***
// tab-width: 4 ***
// c-basic-offset: 4 ***
// indent-tabs-mode: nil ***
// End: ***
// ex: shiftwidth=4 tabstop=4
