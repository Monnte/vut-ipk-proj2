/**
 * @file main.cpp
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @brief Network packet capturing with filter options
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "main.h"

int main(int argc,char** argv) {
	/***---------------------------------------------------------------***/
	/* Inicialization */

	_sniffer = sniffer();
	signal(SIGINT,handle_exit);


	/***---------------------------------------------------------------***/
	/** Arugment Parsing
	 * @see https://www.gnu.org/software/libc/manual/html_node/Getopt.html
	*/


	/* Variables and flags */
	char* interface = NULL;
	string filter = "tcp or udp or arp or icmp or icmp6";
	int udp = 0;
	int tcp = 0;
	int arp = 0;
	int icmp = 0;
	int port = 0;
	int port_flag = 0;
	long packet_cnt = 1;
	char* ptrEnd;

	static struct option long_options[] = {
		{"udp", no_argument, &udp, 1},
		{"tcp", no_argument, &tcp, 1},
		{"arp", no_argument, &arp, 1},
		{"icmp", no_argument, &icmp, 1},
		{"interface", optional_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0},

	};

	/* Parse options and arguments */
	int c;
	while ((c = getopt_long(argc,argv,"uti::p:n:h",long_options,NULL)) != -1) {
		switch (c) {
		case 0:
			break;
		case 'u':
			udp = 1;
			break;
		case 't':
			tcp = 1;
			break;
		case 'i':
			/** Optional i arguemnt
			 * @see https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
			*/
			if (!optarg && optind < argc && NULL != argv[optind] && '\0' != argv[optind][0] && '-' != argv[optind][0])
				interface = argv[optind++];
			else if (!optarg)
				return _sniffer.print_interfaces();
			else
				interface = optarg;
			break;
		case 'p':
			port = std::strtol(optarg,&ptrEnd,10);
			port_flag = 1;
			if (*ptrEnd != '\0') {
				fprintf(stderr,"-p argument must be integer\n");
				return 1;
			}
			break;
		case 'n':
			packet_cnt = std::strtol(optarg,&ptrEnd,10);
			if (*ptrEnd != '\0') {
				fprintf(stderr,"-n argument must be integer\n");
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

	if (!interface) {
		fprintf(stderr,"Error: -i option is requried\n");
		print_help();
		return 1;
	}

	if (port_flag && (port < 1 || port > 65535)) {
		fprintf(stderr,"Error: port is out of range valid ports\n");
		return 1;
	}

	if (packet_cnt <= 0) {
		fprintf(stderr,"Error: packet count must positive integer\n");
		return 1;
	}

	if (udp + tcp + arp + icmp + port > 0) {
		filter = set_filter(port,tcp,udp,icmp,arp);
	}

	/***---------------------------------------------------------------***/
	/* Sniffing packets and printing */

	int timeout = 1000; // 1s
	int promisc = 1;
	if (_sniffer.init(interface,(char*)(filter.c_str()),timeout,promisc,packet_cnt)) {
		return 1;
	}

	if (_sniffer.datalink_type != DLT_EN10MB) {
		fprintf(stderr,"Error: only ethernet support is available\n");
		return 1;
	}
	if (_sniffer.capture_packets()) {
		fprintf(stderr,"Error: an error has occurred while capturing packets\n");
		return 1;
	}

	/***---------------------------------------------------------------***/

	return 0;
}

string set_filter(int port,int tcp,int udp,int icmp,int arp) {
	string filter = "";

	filter += tcp ? (filter.size() ? " or tcp" : "(tcp") : "";
	filter += udp ? (filter.size() ? " or udp" : "(udp") : "";
	filter += arp ? (filter.size() ? " or arp" : "(arp") : "";
	filter += icmp ? (filter.size() ? " or icmp or icmp6" : "(icmp or icmp6") : "";
	filter += filter.size() ? ")" : "";
	filter += port ? (filter.size() ? " and port " + to_string(port) : "port " + to_string(port)) : "";

	return filter;
}

void handle_exit(int s) {
	if (s == 2)
	{
		fprintf(stderr,"\nShutting down sniffer...\n");
		_sniffer.exit_sniffer();
		exit(1);
	}
}

void print_help() {
	printf("------------------------\n");
	printf("Packet sniffer v0.1\n");
	printf("Usage:");
	printf("  ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n packet_cnt}\n\n");
	printf("    [] - requried options\n");
	printf("    {} - optional options\n\n");
	printf("    [ -i iterface | --interface interface ]  - The name of the device on which we will sniff.\n");
	printf("                                               Whithout argument print all available network devices\n");
	printf("    {-p ­­port}                                - Port filter\n");
	printf("    {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} - Packet types filters\n");
	printf("    {-n num}                                 - Number of packets to be printed\n");
	printf("    {-h | --help}                            - Print help message\n");
	printf("\nAuthor: Peter Zdravecký\n");
	printf("------------------------\n");
}