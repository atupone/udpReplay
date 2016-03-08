#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "udpCallback.h"

int main(int argc, char* argv[])
{
  int c;
  const char *pcapName;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap;

  dvalue = NULL;
  flood = 0;
  oneByOne = 0;
  while ((c = getopt(argc, argv, "1fd:")) != -1)
    switch (c) {
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
