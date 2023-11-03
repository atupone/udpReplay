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

#include "udpCallback.h"

int main(int argc, char* argv[])
{
  int c;
  const char *pcapName;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  struct option long_options[] = {
    {"step",  no_argument,       0, '1'},
    {"flood", optional_argument, 0, 'f'},
    {"dest",  required_argument, 0, 'd'},
    {"port",  required_argument, 0, 'p'},
    {"astx",  no_argument,       0, 4},
    {"mttl",  required_argument, 0, 1},
    {0,       0,                 0, 0}
  };
  int option_index;

  while ((c = getopt_long(argc, argv, "1f::d:p:", long_options, &option_index)) != -1)
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
      default:
        break;
    };

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
