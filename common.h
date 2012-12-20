/*
<EtherDogs is a Simple Multi Protocol Packet Sniffer
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

#include<netinet/in.h>		//For BSD Sockets
#include<errno.h>		//For Errors
#include<netdb.h>		//For BSD Sockets
#include<stdio.h>		//For standard all things
#include<stdlib.h>		//For malloc
#include<string.h>		//For strlen

#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>		//Provides declarations for udp header
#include<netinet/tcp.h>		//Provides declarations for tcp header
#include<netinet/ip.h>		//Provides declarations for ip header
#include<netinet/if_ether.h>	//For ETH_P_ALL
#include<net/ethernet.h>	//For ether_header
#include<sys/socket.h>		//For Create the Socket
#include<arpa/inet.h>		//For ARPA
#include<sys/ioctl.h>		//
#include<sys/time.h>		//For time
#include<sys/types.h>		//For BSD Sockets
#include<unistd.h>		//

/*function prototipes*/
void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);
int main();

/*exter global vars and struct declarations*/
extern FILE *dogslog;
extern struct sockaddr_in source,dest;
extern int tcp, udp, icmp, others ,igmp ,total , i, j;

#endif /*end __common_h*/
