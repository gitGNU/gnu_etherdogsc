/*
<EtherDogs is a Simple Multi Protocol Packet Sniffer>
Copyright © <2012-2013> <Jose Maria Micoli>

This file is part of EtherDogs.

    EtherDogs is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    EtherDogs is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with EtherDogs. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __common_h
#define __common_h

#include <pcap.h>            //for use libpcap functions
#include <stdio.h>           //for all thinks
#include <stdlib.h>	   // for exit()
#include <unistd.h>		          
#include <string.h>          //for memset
#include <sys/socket.h>      //for bsd sockets
#include <arpa/inet.h>       // for inet_ntoa()
#include <net/ethernet.h>    //for ethernet header
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>	    //Provides declarations for udp header
#include <netinet/tcp.h>	    //Provides declarations for tcp header
#include <netinet/ip.h>	    //Provides declarations for ip header

#define ICMP 1
#define UDP  17
#define IGMP 2
#define TCP  6

/*function prototipes*/
void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char *, int);
void print_ip_packet(const u_char *, int);
void print_tcp_packet(const u_char *, int);
void print_udp_packet(const u_char *, int);
void print_icmp_packet(const u_char *, int);
void printData(const u_char *, int);
void process_proto(const u_char *, const u_char *);
void process_proto_packet(u_char *, const struct pcap_pkthdr *,const u_char *);

int main();

/*global var, const and struct declarations (only extern)*/
extern FILE *dogslog;
extern struct sockaddr_in source, dest;
extern int tcp, udp, icmp, others, igmp, total,common, i,proto_flag,dev_flag,j;

#endif /*__common_h*/
