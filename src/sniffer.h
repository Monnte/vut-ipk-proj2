/**
 * @file sniffer.h
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#pragma once

 /**
  * @see https://www.tcpdump.org/manpages/pcap.3pcap.html
  */
#include <pcap/pcap.h>
#include "packet.h"

  /**
   * @brief function for pcap_loop callback for handling packets
   *
   * @param user user data passed from pcap_loop fucntion
   * @param pkt_header packet header information (time / packet length)
   * @param pkt_data packet data
   */
void handle_packet(u_char* user,const struct pcap_pkthdr* pkt_header,const u_char* pkt_data);


class sniffer
{
public:
	/**
	 * @brief Construct a new sniffer object
	 */
	sniffer();

	/**
	 * @brief Destroy the sniffer object
	 */
	~sniffer();

	/**
	 * @brief Inicialization for sniffer object. Sets the default value for sniffer
	 *
	 * @param interface interface name
	 * @param filter
	 * @param timeout packet buffer timeout
	 * @param promisc promiscuous mode
	 * @param packet_cnt number of packets that will be captured
	 * @return 0 - success
	 * @return 1 - error
	 */
	int init(char* interface,char* filter,int timeout,int promisc,int packet_cnt);

	/**
	 * @brief Print all available network devices
	 *
	 * @return 0 - success
	 * @return 1 - error
	 */
	int print_interfaces();

	/**
	 * @brief Stars sniffing packets on network
	 *
	 * @return 0 - success
	 * @return 1 - error
	 */
	int capture_packets();

	/**
	 * @brief Correctly stop sniffer from sniffing loop.
	 *
	 */
	void exit_sniffer();

	/* Variables */
	int datalink_type;
	bool loop_running;

private:

	/* Variables */
	char error_message[PCAP_ERRBUF_SIZE];
	char* filter;
	char* interface;
	int timeout;
	int promisc;
	int packet_cnt;
	pcap_t* device;
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct bpf_program fp;
};