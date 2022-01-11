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

#include "udpCallback.h"

int main(int argc, char* argv[])
{
  int c;
  const char *pcapName;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;
  struct option long_options[] = {
    {"step",  no_argument,       0, '1'},
    {"flood", no_argument,       0, 'f'},
    {"dest",  required_argument, 0, 'd'},
    {"astx",  no_argument,       0, 4},
    {0,       0,                 0, 0}
  };
  int option_index;

  dvalue = NULL;
  flood = 0;
  oneByOne = 0;
  while ((c = getopt_long(argc, argv, "1fd:", long_options, &option_index)) != -1)
    switch (c) {
      case 4:
        asterixTime = 1;
        break;
      case '1':
        oneByOne = 1;
        break;
      case 'f':
        flood = 1;
        break;
      case 'd':
        dvalue = optarg;
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

  pcap = pcap_open_offline(pcapName, errbuf);

  if (pcap == NULL) {
    printf("Open of pcap file [%s] failed: %s\n", pcapName, errbuf);
    return -1;
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
