#
#<EtherDogs is a Simple Multi Protocol Packet Sniffer>
#Copyright © <2012-2013> <Jose Maria Micoli>
#
#This file is part of EtherDogs.
#
#    EtherDogs is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    EtherDogs is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with EtherDogs. If not, see <http://www.gnu.org/licenses/>.


etherdogs:main.c data.c ether.c ip.c udp.c tcp.c icmp.c help.c proto.c
etherdogs:main.c data.c ether.c ip.c udp.c tcp.c icmp.c help.c
	gcc -c  main.c data.c ether.c ip.c udp.c tcp.c icmp.c help.c proto.c -lpcap
	gcc -o etherdogs  main.o data.o ether.o ip.o udp.o tcp.o icmp.o help.o proto.o -lpcap
clean:
	rm *.o
	rm etherdogs
install:
	cp etherdogs /usr/bin/
remove:
	rm /usr/bin/etherdogs
debug:
	gcc -g -o etherdogs_dbg main.c data.c ether.c ip.c udp.c tcp.c icmp.c help.c proto.c -lpcap
