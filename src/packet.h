/**
 * @file packet.h
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

#include <stdio.h>
/**
 * @see https://www.tcpdump.org/manpages/pcap.3pcap.html
 */
#include <pcap/pcap.h>

#include <ctype.h>
#include <math.h>
#include <string.h>
#include <string>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using namespace std;

#define LENGTH_CHECK(expected, got)                                                                                                                                                                    \
    if ((expected) > (got)) {                                                                                                                                                                          \
        fprintf(stderr, "Warning: Corrupted packet, skipping...\n");                                                                                                                                   \
        return;                                                                                                                                                                                        \
    }

class packet {
  public:
    /**
     * @brief Construct a new packet object
     *
     * @param pkt_header packet header information (time / packet length)
     * @param pkt_data packet data
     */
    packet(const pcap_pkthdr *pkt_header, const u_char *pkt_data);

    /**
     * @brief Destroy the packet object
     */
    ~packet();

    /**
     * @brief Print packet header and data
     */
    void print_packet();

    /**
     * @brief print metada information from packet
     */
    void print_header();

    /**
     * @brief Print formated data from packet
     */
    void print_data();

    /**
     * @brief Parse ethernet packet based on type
     */
    void parse();

    /* Variables */
    bool is_parsed;

  private:
    /**
     * @brief Handling and parsing ipv4 packets by protocol. Protocols ( UDP | TCP | ICMP )
     */
    void handle_ip_packet();

    /**
     * @brief Handling and parsing ipv6 packets by protocol. Protocols ( UDP | TCP | ICMP6 )
     */
    void handle_ip6_packet();

    /**
     * @brief Handling arp parsing arp packets.
     */
    void handle_arp_packet();

    /**
     * @brief Get the packet capture timestamp
     *
     * @return packet timestamp in RFC3339 format
     */
    string get_packet_time();

    /* Variables */
    const struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    string header;
};