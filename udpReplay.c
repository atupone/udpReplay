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

#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "udpCallback.h"

void help()
{
  printf("udpreplay [-options..] pcap-file\n"
      "where options include: \n"
      "       -1|--step \n"
      "              Send the datagram one by one waiting for input from console to send the next \n"
      "       -f[waitingTime]|--flood[=waitingTime] \n"
      "              Send the datagram as fast as it can, delaying each packet only by waitingTime msec. 1 msec if parameter is missing \n"
      "       --astx Adjust the Asterix Time Of Day to reflect the time the message is sent \n"
      "       -d host|--dest host \n"
      "              Send the datagram to the specified host. It this option is not present, data are sent to the original host as recorded in the pcap file \n"
      "       -p port|--port port \n"
      "              Send the datagram to the specified port. It this option is not present, data are sent to the original port as recorded in the pcap file \n"
      "       --mttl ttlValue \n"
      "              Set the time to live for multicast packets to the value specified as argument. Otherwise is set to 1 \n"
      "       -l[waitingTime]|--loop[=waitingTime] \n"
      "              Send all packets in the pcap file, wait for the specified msec (1 msec if parameter is missing), and loops. \n"
      "\n"
      "       pcap-file   the file that contain the datagram to be sent. It should be in the pcap format \n"
      );
}

static int startSingleReplay(const char *pcapName);

int main(int argc, char* argv[])
{
  int c;
  const char *pcapName;
  struct option long_options[] = {
    {"step",  no_argument,       0, '1'},
    {"flood", optional_argument, 0, 'f'},
    {"loop",  optional_argument, 0, 'l'},
    {"dest",  required_argument, 0, 'd'},
    {"port",  required_argument, 0, 'p'},
    {"astx",  no_argument,       0, 4},
    {"mttl",  required_argument, 0, 1},
    {"help",  no_argument,       0, 'h'},
    {0,       0,                 0, 0}
  };
  int option_index;

  while ((c = getopt_long(argc, argv, "1f::l::d:p:h", long_options, &option_index)) != -1)
    switch (c) {
      case 1:
        setMulticastTTL = 1;
        multicastTTLValue = strtol(optarg, NULL, 0);
        break;
      case 4:
        asterixTime = 1;
        break;
      case '1':
        oneByOne = 1;
        break;
      case 'f':
        flood = 1;
        if (optarg)
          floodTime = strtol(optarg, NULL, 0) * 1000;
        break;
      case 'd':
        dvalue = optarg;
        break;
      case 'p':
        pvalue = optarg;
        break;
      case 'l':
        loop = 1;
        if (optarg)
          loopTime = strtol(optarg, NULL, 0) * 1000;
        break;
      case 'h':
        help();
        return 0;
      case '?':
        printf("Unknown option\n");
        break;
      default:
        printf("Unknown: getopt_long returned == %d\n", c );
        break;
    }

  if (oneByOne == 1 && flood == 1) {
    printf("You cannot specify both -1 and -f\n");
    return -1;
  }

  if (optind == argc) {
    printf("Missing pcap file name\n");
    return -1;
  }

  pcapName = argv[optind];

  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;

  if (dvalue) {
    int result = inet_pton(AF_INET, dvalue, &sockaddr.sin_addr);
    if (!result) {
      printf("-d %s option does not represent a valid host\n", dvalue);
      return -1;
    } else if (result < 0) {
      perror("Converting -d option to valid host fails");
      return -1;
    }
  }
  if (pvalue) {
    int port = atoi(pvalue);
    if (port <= 0) {
      printf("-p %s option is an invalid number or zero\n", pvalue);
      return -1;
    }
    if (port > 65535) {
      printf("-p %s option is greater then 65535\n", pvalue);
      return -1;
    }
    sockaddr.sin_port = htons(port);
  }

  do {
    int result = startSingleReplay(pcapName);
    if (result)
      return result;

    // debug
    time_t tm;
    time(&tm);
    printf("Current date and time: %s\n", ctime(&tm));
    // debug
  } while( loop && ! waitToLoop());

  return 0;
}

int startSingleReplay(const char *pcapName)
{
  pcap_t *pcap;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap = pcap_open_offline(pcapName, errbuf);

  if (pcap == NULL) {
    printf("Open of pcap file [%s] failed: %s\n", pcapName, errbuf);
    return -1;
  }

  datalink = pcap_datalink(pcap);

  if (datalink != DLT_EN10MB)
    if (datalink != DLT_RAW) {
      printf("datalink = %i not handled\n", datalink);
    }
  replayAll(pcap);

  return 0;
}

// Local Variables: ***
// mode: C ***
// tab-width: 2 ***
// c-basic-offset: 2 ***
// indent-tabs-mode: nil ***
// End: ***
// ex: shiftwidth=2 tabstop=2
