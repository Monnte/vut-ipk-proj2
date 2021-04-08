#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string>
#include <string.h>
#include <time.h>
#include <math.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/** @see http://www.ferrisxu.com/WinPcap/html/funcs_2pcap_8h.html 
*/
#include <pcap/pcap.h>

/** TIME
 * @see https://tools.ietf.org/html/rfc3339#section-5.8
 * 
*/

void print_help();
int print_interfaces();
void printTimeRFC3339(struct pcap_pkthdr pkt_header);
void print_packet(const u_char *pkt_data, int size);
void pkt_handle(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
