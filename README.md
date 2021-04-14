# Packet sniffer

Author: Peter Zdravecký

# Introduction

Packet sniffer is program used for packet sniffing on network devices.
Ethernet datalink support only. IPv4 and IPv6 support.

# Packet filtering

Sniffer supports packets filtering.
Filter options can be combined.
Port filter and packet type filter is available.

## Supported packets types

- TCP
- UDP
- ICMP
- ICMP6
- ARP

# How to build project

```
$ make - to build program
$ make clean - to clean temporary files and binary file
```

# Options

```
[] - requried
{} - optional

[ -i iterface | --interface interface ] - The name of the device on which we will sniff.
                               Whithout argument print all available network devices
{-p ­­port} - Port filter
{[--tcp|-t] [--udp|-u] [--arp] [--icmp]} - Packet types filters
{-n num} - Number of packets to be printed
{-h | --help} - Print help message
```

# Example usage

Run program with root acess `sudo`

```
$ ./ipk-sniffer -i eth0
$ ./ipk-sniffer -i eth0 -p 23 --tcp -n 1
$ ./ipk-sniffer -i eth0 --udp
$ ./ipk-sniffer -i lo --udp --tcp -p 80 -n 100
$ ./ipk-sniffer --help
```

# Example sniffer output

```
2021-04-12T21:16:24.219+02:00 127.0.0.1 > 127.0.0.1, length 98 bytes

0x0000:  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00  ........ ......E.
0x0010:  00 54 3B 89 40 00 40 01 01 1E 7F 00 00 01 7F 00  .T;.@.@. ........
0x0020:  00 01 08 00 C3 9F 00 37 00 01 88 9C 74 60 00 00  .......7 ....t`..
0x0030:  00 00 75 58 03 00 00 00 00 00 10 11 12 13 14 15  ..uX.... ........
0x0040:  16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25  ........ .. !"#$%
0x0050:  26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35  &'()*+,- ./012345
0x0060:  36 37                                            67
```

# Project files

```
./Makefile
./README.md
./manual.pdf
./src/main.cpp
./src/main.h
./src/packet.cpp
./src/packet.h
./src/sniffer.cpp
./src/sniffer.h
```
