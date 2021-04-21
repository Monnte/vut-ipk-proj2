/**
 * @file sniffer.cpp
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "sniffer.h"

sniffer::sniffer()
{
}

sniffer::~sniffer()
{
}

int sniffer::init(char *interface, char *filter, int timeout, int promisc, int packet_cnt)
{
	this->interface = interface;
	this->filter = filter;
	this->timeout = timeout;
	this->promisc = promisc;
	this->packet_cnt = packet_cnt;

	if (pcap_lookupnet(this->interface, &(this->netp), &(this->maskp), this->error_message) == -1)
	{
		fprintf(stderr, "Error: %s\n", error_message);
		return 1;
	}

	this->device = pcap_open_live(this->interface, BUFSIZ, this->promisc, this->timeout, this->error_message);
	if (this->device == NULL)
	{
		fprintf(stderr, "Error: %s\n", this->error_message);
		return 1;
	}

	int compile = pcap_compile(this->device, &(this->fp), this->filter, 0, this->netp);
	if (compile == -1)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
		return 1;
	}

	int setfilter = pcap_setfilter(this->device, &(this->fp));
	if (setfilter == -1)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
		return 1;
	}

	this->datalink_type = pcap_datalink(this->device);
	if (this->datalink_type < 0)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(this->device));
		return 1;
	}

	pcap_freecode(&(this->fp));
	return 0;
}

int sniffer::capture_packets()
{
	this->loop_running = true;
	if (pcap_loop(this->device, this->packet_cnt, handle_packet, NULL) < 0)
	{
		fprintf(stderr, "Error: error occures while capturing packets\n");
		return 1;
	}
	this->loop_running = false;

	pcap_close(this->device);

	return 0;
}

void handle_packet(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	if (pkt_header->caplen != pkt_header->len)
	{
		fprintf(stderr, "Warning: Corrupted packet, skipping packet.");
		return;
	}

	packet *_packet = new packet(pkt_header, pkt_data);
	_packet->parse();

	if (_packet->is_parsed)
		_packet->print_packet();

	delete _packet;
}

int sniffer::print_interfaces()
{
	pcap_if_t *interfaces;

	if (pcap_findalldevs(&interfaces, this->error_message) == -1)
	{
		fprintf(stderr, "Error: %s\n", this->error_message);
		return 1;
	}

	for (pcap_if_t *interface = interfaces; interface; interface = interface->next)
	{
		printf("%s\n", interface->name);
	}

	pcap_freealldevs(interfaces);
	return 0;
}

void sniffer::exit_sniffer()
{
	if (this->loop_running)
	{
		pcap_breakloop(this->device);
		pcap_close(this->device);
	}
}