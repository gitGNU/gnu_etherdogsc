#
#<EtherDogs is a Simple Multi Protocol Packet Sniffer>
#Copyright © <2012-2013> <Jose Maria Micoli>
#
#This file is part of EtherDogs.
#
#    EtherDogs is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#	    the Free Software Foundation, either version 3 of the License, or
#	        (at your option) any later version.
#
#    EtherDogs is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#	    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	        GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#        along with EtherDogs. If not, see <http://www.gnu.org/licenses/>.
#	
#
etherdogs:main.c ether.c icmp.c ip.c tcp.c udp.c data.c
	gcc -c main.c ether.c icmp.c ip.c tcp.c udp.c data.c
	gcc main.o ether.o icmp.o ip.o tcp.o udp.o data.o -o etherdogs
clean:
	rm *.o
	rm etherdogs
remove:
	rm /usr/bin/etherdogs
install:
	cp etherdogs /usr/bin/
