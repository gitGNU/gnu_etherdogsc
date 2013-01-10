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

FILE *dogslog;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
int proto = 0;
int main(int argc, char **argv){
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	u_char *filter;
	int count = 1 , n;

	if(argc == 2){
		if(strcmp("-h", argv[1]) == 0){
			helpModule();
			return 0;
			}
		
		else{
			printf("invalid parameter\n");
			return 0;
			}
		}

//Get the device name as parameter with "-d" option
	if(argc == 3){
	
		if (strcmp("-d",argv[1]) == 0){
			devname=argv[2];
			goto open;
		}
		
		else {
			printf("invalid parameter\n");
			return 0;
		}

	}
	if(argc == 5){
		proto = 1;
		if(strcmp("-d",argv[1])==0){
			devname=argv[2];
			goto open;	
		}	
		else {
			printf("Invalid Parameter\n");
			return 0;		
		     }	
	}
	
	
	
	else if(argc != 3 && argc != 1 && argc != 5){
		
		printf("invalid parameter\n");
		return 0;
	
	}
	//First get the list of available devices
	printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");
	
	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	
	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

open:
	/* Using flag -p to select protocol  */
	if(proto == 1)		
	{
		if(strcmp("-p",argv[3]) == 0){
			filter = argv[4];
			printf("Capturing %s packets....\n",filter);
			devname = argv[2];	
			proto_capture(devname,filter);	
		}

		else{
		       	printf("Invalid Parameters : Check Usage with 'etherdogs -h'");
		    }	
	}
	
	else

	{
	
		//Open the device for sniffing
		printf("Opening device %s for sniffing ... " , devname);
		handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
		
		if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
			exit(1);
		}
		printf("Done\n");
		
		dogslog=fopen("dogslog.txt","w");
		if(dogslog==NULL) 
		{
			printf("Unable to create file.");
		}
		
		//Put the device in sniff loop
		pcap_loop(handle , -1 , process_packet , NULL);
		
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
