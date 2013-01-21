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
int tcp=0,udp=0,icmp=0,others=0,igmp=0,i,j,n=-1;	
int dev_flag = 0; //psi: i belive all the flags can be put in to one char veribal
u_char filter = 7; //psi: this is 7 becosuse in binary this is 111 wich means all 3 options are true by defult 
pcap_t *handle; //Handle of the device that shall be sniffed
char *devname, devs[100][100],errbuf[100],holder;  // 1 is icmp. 2 is tcp. 4 is udp. so  tcp and udp would be 4+2 = 6 or 4|2 = 6

void startloop()
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
}

int main(int argc, char **argv)
{
	pcap_if_t *alldevsp , *device;
	int  count = 1,command_opt;
	
	//psi: i got rid of the allocation line as it is not needed we can just link a pointer to the arg line

	
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
			    devname = optarg;  //hear is what i do insted
			    break;
			  case 'p':
			    filter = 0;
			    if((strcmp(optarg, "all") == 0) || (strcmp(optarg, "ALL") == 0))
			      {
				filter = 7;
				optarg = optarg+4;
			      }
			    while((*optarg) != '\0')
			      {
				switch(*optarg)
				  {
				  case 'i':
				  case 'I':
				    filter = (filter|1);
				    break;
				  case 't':
				  case 'T':
				    filter = (filter|2);
				    break;
				  case 'u':
				  case 'U':
				    filter = (filter|4);
				    break;
				  defult :
				    printf("unreconised char %c",optarg);
				    exit(1);
				    break;
				  }
				optarg++;
			      }
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
	
	else 
	  {
	    startloop();
	    
	  }	
	

	
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;
	
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	switch (iph->protocol) //Check the Protocol and do accordingly...
	{
	case 1:  //ICMP Protocol
	  ++icmp;
	  if((filter & 1) == 1)
	    {
	      print_icmp_packet( buffer , size);
	    }
	  break;
	  
	case 2:  //IGMP Protocol
	  ++igmp;
	  break;
	  
	case 6:  //TCP Protocol
	  ++tcp;
	  if((filter & 2) == 2)
	    {
	      print_tcp_packet(buffer , size);
	    }
	  break;
	  
	case 17: //UDP Protocol
	  ++udp;
	  if((filter & 4) == 4)
	    {
	      print_udp_packet(buffer , size);
	    }
	  break;
	  
	default: //Some Other Protocol like ARP etc.
	  ++others;
	  break;
	}
	printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , tcp+udp+icmp+igmp+others);

}

void listDevice(void)
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed
	int count = 1;


	char errbuf[100] , *devname , devs[100][100];
	//First get the list of available devices
	//printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	//Print the available devices
	//printf("\nAvailable Devices are :\n");

	for(device = alldevsp ; device != NULL ; device = device->next)
	{	
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}
	if(count > 1)
	  {
	    printf("plese enter the number of the device you want\n");
	    holder = getchar();
	    if(isdigit(holder))
	      {
	    devname = devs[holder];
	    dev_flag = 1;
	    startloop();
	      }
	    else
	      {
		printf("was not decimal number/n");
	      }
	  }
	
}


