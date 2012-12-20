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
    along with EtherDogs.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"

FILE *dogslog;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	

int main(){

	int saddr_size , data_size;
	struct sockaddr saddr;
		
	unsigned char *buffer = (unsigned char *) malloc(65536); //Its Big!
	
	dogslog=fopen("dogslog.txt","w");
	if(dogslog==NULL) {
		printf("Unable to create smpps.txt file.");
		}
    printf("\n\tEtherDogs Release 1.0 Beta\n\nCopyright (C) 2012-2013  Jose Maria Micoli\nThis program is free software: you can redistribute it and/or modify\nit under the terms of the GNU General Public License as published by\nthe Free Software Foundation, either version 3 of the License, or\n(at your option) any later version.\n\nThis program is distributed in the hope that it will be useful,\nbut WITHOUT ANY WARRANTY; without even the implied warranty of\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\nGNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License\nalong with this program.  If not, see <http://www.gnu.org/licenses/>.\n\n");
	printf("Starting capture...\n");
	
	int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
	//setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
	
	if(sock_raw < 0){
		//Print the error with proper message
		perror("Socket Error");
		return 1;
		}
	while(1){
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
		if(data_size <0 ){
			printf("Recvfrom error , failed to get packets\n");
			return 1;
			}
		//Now process the packet
		ProcessPacket(buffer , data_size);
		}
	close(sock_raw);
	printf("Finished");
	return 0;
}

void ProcessPacket(unsigned char* buffer, int size){
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	switch (iph->protocol){ //Check the Protocol and do accordingly...
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

