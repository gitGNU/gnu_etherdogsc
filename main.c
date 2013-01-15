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

FILE *dogslog;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
int proto_flag = 0, dev_flag = 0;

int main(int argc, char ** argv)
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	u_char *filter;
	int count = 1 , n=-1,command_opt;
	

	//allocate memory for devname and filter
	
	devname = (char *)malloc(20*sizeof(char));
	filter = (u_char *)malloc(20*sizeof(u_char));
	

	
	if(argc>=2)
	{
		while((command_opt=getopt(argc,argv,"hld:p:n:"))!=-1)
		{
			

			switch(command_opt)
			{
				case 'l':
					listDevice();
					exit(2);
					break;
				case 'h':
					helpModule();
					exit(2);	
					break;
				case 'd':
					dev_flag = 1;
					strcpy(devname,optarg); 
					break;
				case 'p':
					proto_flag = 1;
					strcpy(filter,optarg);
					break;
				case 'n':
					n = atoi(optarg);
					break;
				case '?':
					break;
				
				default :printf("getopt returned code : %c ",command_opt);
		
			}
		}

	}

	if(optind < argc)
	{
		printf("Invalid Options : ");
		while(optind<argc)
			printf("%s ",argv[optind++]);
		printf("\n");
		printf("Use etherdogs -h for help or etherdogs -l to list the all available devices \n");
		return 0;
	}

	if((argc==1) || !dev_flag)
	{
		printf("Usage: etherdogs -d <device> -p <protocol> -n <max number of packets>\n");
		printf("Use etherdogs -h for help or etherdogs -l to list the all available devices\n");
		return 1;	
	}


	if(proto_flag == 1)
	{
		proto_capture(devname,filter);
		return 0;
	}
	
	else 
	{
		//Open the device for sniffing
		printf("Opening device '%s' for sniffing ... " , devname);
		handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
		
		if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open device '%s' : %s\n" , devname , errbuf);
			exit(1);
		}
		printf("Done\n");
		
		dogslog=fopen("dogslog.txt","w");
		if(dogslog==NULL) 
		{
			printf("Unable to create file.");
		}		
			//Put the device in sniff loop
			pcap_loop(handle , n , process_packet , NULL);
			printf("\n");
			return 0;
		
	}	


	
}	
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			++icmp;
			print_icmp_packet( buffer , size);
			break;
		
		case 2:  //IGMP Protocol
			++igmp;
			break;
		
		case 6:  //TCP Protocol
			++tcp;
			print_tcp_packet(buffer , size);
			break;
		
		case 17: //UDP Protocol
			++udp;
			print_udp_packet(buffer , size);
			break;
		
		default: //Some Other Protocol like ARP etc.
			++others;
			break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);

}
