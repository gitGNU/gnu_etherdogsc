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
	
		if(strcmp(args,"ICMP")==0){ //ICMP Protocol
			++icmp;
			++common;
			print_icmp_packet( buffer , size);
		}
		
		else if(strcmp(args,"IGMP")==0){  //IGMP Protocol
			++igmp;
			++common;
		}
		
		else if(strcmp(args,"TCP")==0){  //TCP Protocol
			++tcp;
			++common;
			print_tcp_packet(buffer , size);
		}
		
		else if(strcmp(args,"UDP")==0){ //UDP Protocol
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
