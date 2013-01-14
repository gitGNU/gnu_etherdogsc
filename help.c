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
	printf("\nusage: etherdogs -'' <parameters>\nexample: etherdogs -h //for help\n\tetherdogs -d <device> -p <filter>\n");
	printf("or for simple run the ether dogs usage is: etherdogs //To list every available network interfaces\n");
	printf("\nList of any arguments:\n");
	printf("\t-h For help\n");
	printf("\t-d For select the device\n");
	printf("\t-p For filter captured packets\n");
	printf("\t-n For max number of packet to capture\n\n");
	
}
