#include "main.h"

int main(int argc, char **argv)
{

	/* Arugment Parsing */
	/** @see https://www.gnu.org/software/libc/manual/html_node/Getopt.html */

	std::string interface = "eth0";
	int udp = 0;
	int tcp = 0;
	int arp = 0;
	int icmp = 0;
	int port = 23;
	int num = 10;
	char *ptrEnd[2];

	static struct option long_options[] =
		{
			{"udp", no_argument, &udp, 1},
			{"tcp", no_argument, &tcp, 1},
			{"arp", no_argument, &arp, 1},
			{"icmp", no_argument, &icmp, 1},
			{"interface", required_argument, nullptr, 'i'},
			{0, 0, 0, 0},

		};

	int c;
	while ((c = getopt_long(argc, argv, "uti::p:n:", long_options, nullptr)) != -1)
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
				return printInterfaces();
			else
				interface = optarg;
			break;
		case 'p':
			port = std::strtol(optarg, &ptrEnd[0], 10);
			if (*ptrEnd[0] != '\0')
			{
				std::cout << "-p argument must be integer" << std::endl;
				return 1;
			}
			break;
		case 'n':
			num = std::strtol(optarg, &ptrEnd[1], 10);
			if (*ptrEnd[1] != '\0')
			{
				std::cout << "-n argument must be integer" << std::endl;
				return 1;
			}
			break;
		case '?':
			return 1;
			break;
		default:
			return 1;
		}
	}

	if (!udp && !tcp && !arp && !icmp)
	{
		std::cout << "[--tcp|-t] [--udp|-u] [--arp] [--icmp] at least one option is requried" << std::endl;
		return 1;
	}

	std::cout << "interface: " << interface << std::endl;
	printf("udp: %d\n", udp);
	printf("tcp: %d\n", tcp);
	printf("arp: %d\n", arp);
	printf("icmp: %d\n", icmp);
	printf("port: %d\n", port);
	printf("num: %d\n", num);
}

int printInterfaces()
{
	char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *interface;

	if (pcap_findalldevs(&interfaces, error) == -1)
	{
		printf("Error: %s\n", error);
		return 1;
	}

	for (interface = interfaces; interface; interface = interface->next)
	{
		printf("%s\n", interface->name);
	}

	return 0;
}