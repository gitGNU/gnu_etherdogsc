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

void print_ip_header(const u_char * Buffer, int Size)
{
	print_ethernet_header(Buffer , Size);
  
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	fprintf(dogslog , "\n");
	fprintf(dogslog , "IP Header\n");
	fprintf(dogslog , "   |-IP Version        : %d\n",(unsigned int)iph->version);
	fprintf(dogslog , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	fprintf(dogslog , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	fprintf(dogslog , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	fprintf(dogslog , "   |-Identification    : %d\n",ntohs(iph->id));
	//fprintf(dogslog , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	//fprintf(dogslog , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	//fprintf(dogslog , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	fprintf(dogslog , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
	fprintf(dogslog , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
	fprintf(dogslog , "   |-Checksum : %d\n",ntohs(iph->check));
	fprintf(dogslog , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	fprintf(dogslog , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
