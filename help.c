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

void helpModule(void)
{
	printf("\n\tEtherDogs Release 1.0 Beta\n\nCopyright (C) 2012-2013  Jose Maria Micoli\nThis program is free software: you can redistribute it and/or modify\nit under the terms of the GNU General Public License as published by\nthe Free Software Foundation, either version 3 of the License, or\n(at your option) any later version.\n\nThis program is distributed in the hope that it will be useful,\nbut WITHOUT ANY WARRANTY; without even the implied warranty of\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\nGNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License\nalong with this program. If not, see <http://www.gnu.org/licenses/>.\n\n");
	printf("\nWelcome to the EtherDogs\nEtherDogs is a simple multi protocol packet sniffer\n");
	printf("EtherDogs is a Free Software\n");
	printf("\nThis is the help module\n\n");
	printf("\nUsage: etherdogs -d <device> -p <protocol> -n <max number of packets\n>");
	printf("Or use etherdogs -h for Help or etherdogs -l to list all available devices\n");
	printf("\nList of any arguments:\n");
	printf("\t-l For list all available Device\n");
	printf("\t-h For help\n");
	printf("\t-d For select the device\n");
	printf("\t-p For filter captured packets\n");
	printf("\t-n For max number of packet to capture\n\n");
	
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

}
