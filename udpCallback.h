#include <pcap/pcap.h>

extern struct sockaddr_in sockaddr;
extern int rewriteDestination;
extern char *dvalue;
extern int flood;
extern int oneByOne;

extern void replayAll(pcap_t *pcap);
