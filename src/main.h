/**
 * @file main.h
 * @author Peter zdravecký (xzdrav00@stud.fit.vutbr.cz)
 * @version 0.1
 * @date 2021-04-11
 *
 * @copyright Copyright (c) 2021
 *
 */
#include "sniffer.h"
#include <getopt.h>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace std;

/**
 * @brief Handling keyboard interrupt signal. Correctly shuts down sniffer
 *
 * @param s signal code
 */
void handle_exit(int s);

/**
 * @brief Prints program help and usage
 */
void print_help();

/**
 * @brief Set the filter string. Combines filter options to one
 *
 * @param port port number
 * @param tcp tcp flag
 * @param udp udp flag
 * @param icmp icmp flag
 * @param arp arp flag
 *
 * @return filter string for sniffer
 */

string set_filter(int port, int tcp, int udp, int icmp, int arp, int igmp);

sniffer _sniffer;