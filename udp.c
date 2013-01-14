/*
<EtherDogs is a Simple Multi Protocol Packet Sniffer>
Copyright © <2012-2013> <EtherDogs Development Team>

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

#include "common.h"

void print_udp_packet(const u_char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	fprintf(dogslog , "\n\n***********************UDP Packet*************************\n");
	
	print_ip_header(Buffer,Size);			
	
	fprintf(dogslog , "\nUDP Header\n");
	fprintf(dogslog , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(dogslog , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(dogslog , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(dogslog , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(dogslog , "\n");
	fprintf(dogslog , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(dogslog , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(dogslog , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(dogslog , "\n###########################################################");
}
