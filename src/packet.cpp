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

packet::packet(const pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    this->is_parsed = false;
    this->pkt_header = new pcap_pkthdr;
    this->pkt_data = new u_char[pkt_header->caplen];
    memcpy((void *)(this->pkt_header), pkt_header, sizeof(pcap_pkthdr));
    memcpy((void *)(this->pkt_data), pkt_data, pkt_header->caplen);
}

packet::~packet() {
    delete pkt_header;
    delete[] pkt_data;
}

void packet::print_packet() {
    this->print_header();
    this->print_data();
}

void packet::print_header() { printf("%s", header.c_str()); }

void packet::parse() {
    LENGTH_CHECK(sizeof(ether_header), pkt_header->caplen)
    struct ether_header *eth_header = (struct ether_header *)this->pkt_data;

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

void packet::handle_ip_packet() {
    LENGTH_CHECK(sizeof(ip), pkt_header->caplen - sizeof(ether_header))
    struct ip *ip_header = (struct ip *)(this->pkt_data + sizeof(ether_header));

    char source[INET_ADDRSTRLEN];
    char dest[INET_ADDRSTRLEN];

    strcpy(source, inet_ntoa(ip_header->ip_src));
    strcpy(dest, inet_ntoa(ip_header->ip_dst));
    this->header += get_packet_time();

    switch (ip_header->ip_p) {
    case IPPROTO_TCP: {
        LENGTH_CHECK(sizeof(tcphdr), pkt_header->caplen - sizeof(ether_header) - 4 * ip_header->ip_hl)
        struct tcphdr *tcp_header = (struct tcphdr *)(this->pkt_data + sizeof(ether_header) + 4 * ip_header->ip_hl);

        this->header += source + string(" : ") + to_string(ntohs(tcp_header->source)) + string(" > ") + dest + string(" : ") + to_string(ntohs(tcp_header->dest));
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    }

    break;
    case IPPROTO_UDP: {
        LENGTH_CHECK(sizeof(udphdr), pkt_header->caplen - sizeof(ether_header) - 4 * ip_header->ip_hl)
        struct udphdr *udp_header = (struct udphdr *)(this->pkt_data + sizeof(ether_header) + 4 * ip_header->ip_hl);

        this->header += source + string(" : ") + to_string(ntohs(udp_header->source)) + string(" > ") + dest + string(" : ") + to_string(ntohs(udp_header->dest));
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    } break;
    case IPPROTO_ICMP: {
        this->header += source + string(" > ") + dest;
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    } break;
    case IPPROTO_IGMP: {
        LENGTH_CHECK(sizeof(igmp), pkt_header->caplen - sizeof(ether_header) - 4 * ip_header->ip_hl)
        struct igmp *igmp_header = (struct igmp *)(this->pkt_data + sizeof(igmp) + 4 * ip_header->ip_hl);

        this->header += source + string(" > ") + dest;
        this->header += string(", Message type ") + to_string(igmp_header->igmp_code);
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    }
    default:
        break;
    }
}

void packet::handle_arp_packet() {
    struct ether_header *eth_header = (struct ether_header *)this->pkt_data;
    char source[256];
    char dest[256];

    sprintf(source, "%02x:%02x:%02x:%02x:%02x:%02x", eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2], eth_header->ether_shost[3], eth_header->ether_shost[4],
            eth_header->ether_shost[5]);
    sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x", eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2], eth_header->ether_dhost[3], eth_header->ether_dhost[4],
            eth_header->ether_dhost[5]);

    this->header += get_packet_time();
    this->header += source + string(" > ") + dest;
    this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
    this->is_parsed = true;
}

void packet::handle_ip6_packet() {
    LENGTH_CHECK(sizeof(ip6_hdr), pkt_header->caplen - sizeof(ether_header))
    struct ip6_hdr *ip6_header = (struct ip6_hdr *)(this->pkt_data + sizeof(ether_header));

    char source[INET6_ADDRSTRLEN];
    char dest[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, (const void *)&(ip6_header->ip6_src), source, sizeof(source));
    inet_ntop(AF_INET6, (const void *)&(ip6_header->ip6_dst), dest, sizeof(source));
    this->header += get_packet_time();

    switch (ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
    case IPPROTO_TCP: {
        LENGTH_CHECK(sizeof(tcphdr), pkt_header->caplen - sizeof(ether_header) - sizeof(ip6_header))
        struct tcphdr *tcp_header = (struct tcphdr *)(this->pkt_data + sizeof(ether_header) + sizeof(ip6_hdr));

        this->header += source + string(" : ") + to_string(ntohs(tcp_header->source)) + string(" > ") + dest + string(" : ") + to_string(ntohs(tcp_header->dest));
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    } break;
    case IPPROTO_UDP: {
        LENGTH_CHECK(sizeof(udphdr), pkt_header->caplen - sizeof(ether_header) - sizeof(ip6_header))
        struct udphdr *udp_header = (struct udphdr *)(this->pkt_data + sizeof(ether_header) + sizeof(ip6_hdr));

        this->header += source + string(" : ") + to_string(ntohs(udp_header->source)) + string(" > ") + dest + string(" : ") + to_string(ntohs(udp_header->dest));
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    } break;
    case IPPROTO_ICMPV6: {
        this->header += source + string(" > ") + dest;
        this->header += string(", length ") + to_string(this->pkt_header->len) + string(" bytes\n");
        this->is_parsed = true;
    } break;
    default:
        break;
    }
}

void packet::print_data() {
    printf("\n");
    for (unsigned int i = 0; i < this->pkt_header->caplen;) {
        printf("0x%04x:  ", i);
        char line[17] = "";
        for (int j = 0; j < 16 && i < this->pkt_header->caplen; i++, j++) {
            printf("%02X ", this->pkt_data[i]);
            line[j] = isprint(this->pkt_data[i]) ? this->pkt_data[i] : '.';
        }
        for (; i % 16 != 0; i++) {
            printf("   ");
        }
        printf(" %.8s %.8s\n", line, line + 8);
    }
    printf("\n");
}

string packet::get_packet_time() {
    char timebuffer[50];
    char timebuffer2[50];

    struct tm *tm;
    tm = localtime(&(this->pkt_header->ts.tv_sec));

    strftime(timebuffer, 26, "%Y-%m-%dT%H:%M:%S", tm);

    char sign = tm->tm_gmtoff < 0 ? '-' : '+';
    sprintf(timebuffer2, ".%03d%c%02d:%02ld ", int(round(this->pkt_header->ts.tv_usec / 1000)), sign, int(abs(tm->tm_gmtoff) / 3600), (abs(tm->tm_gmtoff) / 60) % 60);

    return string(timebuffer) + string(timebuffer2);
}