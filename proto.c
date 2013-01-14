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

int common = 0; 
void proto_capture(const u_char * device_name,u_char * protocol_filter)
{
	pcap_t *handle;
	char errbuf[100];
	
	printf("Opening device %s for sniffing ... " , device_name);
	handle = pcap_open_live(device_name , 65536 , 1 , 0 , errbuf);
	
	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n" , device_name , errbuf);
		exit(1);
	}
	printf("Done\n");
	
	dogslog=fopen("dogslog.txt","w");
	if(dogslog==NULL) 
	{
		printf("Unable to create file.");
	}
	
	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_proto_packet ,protocol_filter);
}


void process_proto_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *buffer)
{
	
	int size = header->len;
	 //Check the Protocol and do accordingly...
	
		if((strcmp(args,"ICMP") && strcmp(args,"icmp"))==0){ //ICMP Protocol
			++icmp;
			++common;
			print_icmp_packet( buffer , size);
		}
		
		else if((strcmp(args,"IGMP") && strcmp(args,"igmp"))==0){  //IGMP Protocol
			++igmp;
			++common;
		}
		
		else if((strcmp(args,"TCP") && strcmp(args,"tcp"))==0){  //TCP Protocol
			++tcp;
			++common;
			print_tcp_packet(buffer , size);
		}
		
		else if((strcmp(args,"UDP") && strcmp(args,"udp"))==0){ //UDP Protocol
			++udp;
			++common;
			print_udp_packet(buffer , size);
		}
		
		else {
			//Some Other Protocol like ARP etc.
			++others;
			++common;
		}
			
	
	printf("%s : %d\r",args,common);
}
