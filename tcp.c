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

#include "common.h"

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
			
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	fprintf(dogslog, "\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(Buffer,Size);
		
	fprintf(dogslog, "\n");
	fprintf(dogslog, "TCP Header\n");
	fprintf(dogslog, "   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(dogslog, "   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(dogslog, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(dogslog, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(dogslog , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(dogslog, "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(dogslog, "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(dogslog, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(dogslog, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(dogslog, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(dogslog, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(dogslog, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(dogslog, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(dogslog, "   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(dogslog, "   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(dogslog, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(dogslog, "\n");
	fprintf(dogslog, "                        DATA Dump                         ");
	fprintf(dogslog, "\n");
		
	fprintf(dogslog, "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(dogslog, "TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(dogslog, "Data Payload\n");	
	PrintData(Buffer + header_size , Size - header_size );
						
	fprintf(dogslog, "\n###########################################################");
}

