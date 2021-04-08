#include "main.h"

int main(int argc, char **argv)
{

	/* Arugment Parsing */
	/** @see https://www.gnu.org/software/libc/manual/html_node/Getopt.html */

	char *interface = nullptr;
	int udp = 0;
	int tcp = 0;
	int arp = 0;
	int icmp = 0;
	int port = 0;
	long num = 1;
	char *ptrEnd[2];

	static struct option long_options[] =
		{
			{"udp", no_argument, &udp, 1},
			{"tcp", no_argument, &tcp, 1},
			{"arp", no_argument, &arp, 1},
			{"icmp", no_argument, &icmp, 1},
			{"interface", optional_argument, nullptr, 'i'},
			{"help", no_argument, nullptr, 'h'},
			{0, 0, 0, 0},

		};

	int c;
	while ((c = getopt_long(argc, argv, "uti::p:n:h", long_options, nullptr)) != -1)
	{
		switch (c)
		{
		case 0:
			break;
		case 'u':
			udp = 1;
			break;
		case 't':
			tcp = 1;
			break;
		case 'i':
			/* Optional i arguemnt */
			/** @see https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters */
			if (!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0])
				interface = argv[optind++];
			else if (!optarg)
				return print_interfaces();
			else
				interface = optarg;
			break;
		case 'p':
			port = std::strtol(optarg, &ptrEnd[0], 10);
			if (*ptrEnd[0] != '\0')
			{
				fprintf(stderr, "-p argument must be integer\n");
				return 1;
			}
			break;
		case 'n':
			num = std::strtol(optarg, &ptrEnd[1], 10);
			if (*ptrEnd[1] != '\0')
			{
				fprintf(stderr, "-n argument must be integer\n");
				return 1;
			}
			break;
		case 'h':
			print_help();
			return 0;
			break;
		case '?':
			return 1;
			break;
		default:
			return 1;
		}
	}

	if (!interface)
	{
		return print_interfaces();
	}
	if ((udp + tcp + arp + icmp) > 1)
	{
		fprintf(stderr, "Error: [--tcp|-t] [--udp|-u] [--arp] [--icmp] max one option\n");
		return 1;
	}
	if (port > 65535 || port < 0)
	{
		fprintf(stderr, "Error: port is out of range valid ports\n");
		return 1;
	}

	char errMsg[PCAP_ERRBUF_SIZE];

	bpf_u_int32 ip, maskp;
	if (pcap_lookupnet(interface, &ip, &maskp, errMsg) == -1)
	{
		printf("Error: %s\n", errMsg);
		return 1;
	}

	pcap_t *handle;
	int timeout = 10000;

	handle = pcap_open_live(interface, BUFSIZ, 1, timeout, errMsg);
	if (!handle)
	{
		printf("Error: %s\n", errMsg);
		return 1;
	}

	struct bpf_program fp;
	char filter[200];

	if (port)
	{
		char portStr[20];
		sprintf(portStr, "%d", port);
		strcpy(filter, "port ");
		strcat(filter, portStr);
	}

	if (tcp)
		strcat(filter, " and tcp");
	if (udp)
		strcat(filter, " and udp");
	if (icmp)
		strcat(filter, " and icmp");
	if (arp)
		strcat(filter, " and arp");

	printf("filter: %s\n", filter);

	if (pcap_compile(handle, &fp, filter, 0, ip) == -1)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
		return 1;
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
		return 1;
	}

	if (pcap_loop(handle, num, pkt_handle, NULL) < 0)
	{
		fprintf(stderr, "Error: error occures while capturing packets\n");
		return 1;
	}
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

void pkt_handle(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
	struct iphdr *iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
	case 1: //ICMP Protocol
		printf("ICMP");
		break;

	case 6: //TCP Protocol
		printf("TCP");
		break;

	case 17: //UDP Protocol
		printf("UDP");
		break;
	case 54:
		printf("ARP");
		break;
	case 58: //ICMP for IPv6
		printf("ICMP IPV6");
		break;
	default:
		break;
	}
}

void print_packet(const u_char *pkt_data, int size)
{
	int i;
	for (i = 0; i < size; i++)
	{
		if (i % 16 == 0)
			printf("\n");

		if (i != 0 && i % 16 == 0)
		{
			for (int j = i - 16; j < i; j++)
			{

				printf("%02X ", pkt_data[j]);
			}

			for (int j = i - 16; j < i; j++)
			{
				if (j % 8 == 0)
					printf(" ");
				if (isprint(pkt_data[j]))
					printf("%c", pkt_data[j]);
				else
					printf(".");
			}
		}
	}

	//print restt of packet
	printf("\n");
	for (int j = i - i % 16; j < i; j++)
	{
		printf("%02X ", pkt_data[j]);
	}
	for (int j = i % 16; j < 16; j++)
		printf("   ");
	for (int j = i - i % 16; j < i; j++)
	{
		if (j % 8 == 0)
			printf(" ");
		if (isprint(pkt_data[j]))
			printf("%c", pkt_data[j]);
		else
			printf(".");
	}

	printf("\n\n");
}

int print_interfaces()
{
	char errMsg[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *interface;

	if (pcap_findalldevs(&interfaces, errMsg) == -1)
	{
		printf("Error: %s\n", errMsg);
		return 1;
	}

	for (interface = interfaces; interface; interface = interface->next)
	{
		printf("%s\n", interface->name);
	}

	return 0;
}

void print_help()
{
	printf("Packet sniffer v0.1\n");
	printf("Usage:");
	printf("  ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
	printf("Author: Peter Zdravecký\n");
}

void printTimeRFC3339(struct pcap_pkthdr pkt_header)
{
	struct timeval tv = pkt_header.ts;
	struct tm *tm;
	char time[100];
	char timebuffer[50];

	tm = localtime(&tv.tv_sec);

	strftime(time, 26, "%Y-%m-%dT%H:%M:%S", tm);
	char sign = '+';
	if (tm->tm_gmtoff < 0)
	{
		sign = '-';
	}
	sprintf(timebuffer, ".%03d%c%02d:%02ld", int(round(tv.tv_usec / 1000)), sign, int(abs(tm->tm_gmtoff) / 3600), (abs(tm->tm_gmtoff) / 60) % 60);
	strcat(time, timebuffer);
	printf("%s", time);
}
