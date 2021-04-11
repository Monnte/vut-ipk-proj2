/**
 * @file packet.cpp
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "packet.h"

packet::packet(const pcap_pkthdr* pkt_header,const u_char* pkt_data)
{
	this->pkt_header = new pcap_pkthdr;
	this->pkt_data = new u_char[pkt_header->caplen];
	memcpy((void*)(this->pkt_header),pkt_header,sizeof(pcap_pkthdr));
	memcpy((void*)(this->pkt_data),pkt_data,pkt_header->caplen);
}

packet::~packet()
{
	delete pkt_header;
	delete[] pkt_data;
}

void packet::print_packet()
{
	this->print_header();
	this->print_data();
}

void packet::print_header()
{
	printf("%s",header.c_str());
}

void packet::parse()
{
	struct ether_header* eth_header = (struct ether_header*)this->pkt_data;

	switch (ntohs(eth_header->ether_type)) {
	case ETHERTYPE_IP:
		this->handle_ip_packet();
		break;
	case ETHERTYPE_ARP:
		this->handle_arp_packet();
		break;
	case ETHERTYPE_IPV6:
		this->handle_ip6_packet();
		break;
	default:
		break;
	}
}

void packet::handle_ip_packet()
{
	struct ip* ip_header = (struct ip*)(this->pkt_data + sizeof(ether_header));

	char source[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];

	strcpy(source,inet_ntoa(ip_header->ip_src));
	strcpy(dest,inet_ntoa(ip_header->ip_dst));
	this->header += get_packet_time();

	switch (ip_header->ip_p) {
	case IPPROTO_TCP:
	{
		struct tcphdr* tcp_header = (struct tcphdr*)(this->pkt_data + sizeof(ether_header) + 4 * ip_header->ip_hl);
		this->header += source + std::string(" : ") + std::to_string(ntohs(tcp_header->source)) + std::string(" > ") + dest + std::string(" : ") + std::to_string(ntohs(tcp_header->dest));
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}

	break;
	case IPPROTO_UDP:
	{
		struct udphdr* udp_header = (struct udphdr*)(this->pkt_data + sizeof(ether_header) + 4 * ip_header->ip_hl);
		this->header += source + std::string(" : ") + std::to_string(ntohs(udp_header->source)) + std::string(" > ") + dest + std::string(" : ") + std::to_string(ntohs(udp_header->dest));
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}
	break;
	case IPPROTO_ICMP:
	{
		this->header += source + std::string(" > ") + dest;
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}
	break;
	default:
		break;
	}
}

void packet::handle_arp_packet()
{
	struct ether_arp* arp_header = (struct ether_arp*)(this->pkt_data + sizeof(ether_header));
	char source[INET6_ADDRSTRLEN];
	char dest[INET6_ADDRSTRLEN];

	strcpy(source,inet_ntoa(*(in_addr*)&(arp_header->arp_sha)));
	strcpy(dest,inet_ntoa(*(in_addr*)&(arp_header->arp_tha)));
	this->header += get_packet_time();
	this->header += source + std::string(" > ") + dest;
	this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
	this->is_parsed = true;
}

void packet::handle_ip6_packet()
{
	struct ip6_hdr* ip6_header = (struct ip6_hdr*)(this->pkt_data + sizeof(ether_header));

	char source[AF_INET6];
	char dest[AF_INET6];

	strcpy(source,inet_ntop(AF_INET6,(const void*)&(ip6_header->ip6_src),source,sizeof(source)));
	strcpy(dest,inet_ntop(AF_INET6,(const void*)&(ip6_header->ip6_dst),dest,sizeof(source)));
	this->header += get_packet_time();

	switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
	case IPPROTO_TCP:
	{
		struct tcphdr* tcp_header = (struct tcphdr*)(this->pkt_data + sizeof(ether_header) + sizeof(ip6_hdr));
		this->header += source + std::string(" : ") + std::to_string(ntohs(tcp_header->source)) + std::string(" > ") + dest + std::string(" : ") + std::to_string(ntohs(tcp_header->dest));
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}
	break;
	case IPPROTO_UDP:
	{
		struct udphdr* udp_header = (struct udphdr*)(this->pkt_data + sizeof(ether_header) + sizeof(ip6_hdr));
		this->header += source + std::string(" : ") + std::to_string(ntohs(udp_header->source)) + std::string(" > ") + dest + std::string(" : ") + std::to_string(ntohs(udp_header->dest));
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}
	break;
	case IPPROTO_ICMPV6:
	{
		this->header += source + std::string(" > ") + dest;
		this->header += std::string(", length ") + std::to_string(this->pkt_header->len) + std::string(" bytes\n");
		this->is_parsed = true;
	}
	break;
	default:
		break;
	}
}

void packet::print_data() {
	int size = (int)this->pkt_header->caplen;
	int hexcounter = -16;

	if (size == 0) return;

	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0) {
			printf("\n");
		}

		if (i != 0 && i % 16 == 0) {
			printf("0x%04X:  ",hexcounter += 16);
			for (int j = i - 16; j < i; j++) {

				printf("%02X ",this->pkt_data[j]);
			}

			for (int j = i - 16; j < i; j++) {
				if (j % 8 == 0)
					printf(" ");
				if (isprint(this->pkt_data[j]))
					printf("%c",this->pkt_data[j]);
				else
					printf(".");
			}
		}
	}

	/* REST OF PACKET DATA */
	printf("\n");
	printf("0x%04X:  ",hexcounter += 16);
	for (int j = i - i % 16; j < i; j++) {
		printf("%02X ",this->pkt_data[j]);
	}
	/* PRINT PADDING*/
	for (int j = i % 16; j < 16; j++) {
		printf("   ");
	}

	for (int j = i - i % 16; j < i; j++) {
		if (j % 8 == 0)
			printf(" ");
		if (isprint(this->pkt_data[j]))
			printf("%c",this->pkt_data[j]);
		else
			printf(".");
	}

	printf("\n\n");
}

std::string packet::get_packet_time() {
	struct tm* tm;

	char timebuffer[50];
	char timebuffer2[50];

	tm = localtime(&(this->pkt_header->ts.tv_sec));

	strftime(timebuffer,26,"%Y-%m-%dT%H:%M:%S",tm);
	char sign = tm->tm_gmtoff < 0 ? '-' : '+';
	sprintf(timebuffer2,".%03d%c%02d:%02ld ",int(round(this->pkt_header->ts.tv_usec / 1000)),sign,int(abs(tm->tm_gmtoff) / 3600),(abs(tm->tm_gmtoff) / 60) % 60);

	return std::string(timebuffer) + std::string(timebuffer2);
}