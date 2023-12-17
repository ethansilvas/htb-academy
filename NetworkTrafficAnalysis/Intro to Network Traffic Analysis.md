
## Tcpdump Fundamentals

tcpdump = command-line packet sniffer  
windows twin = WinDump but not supported anymore
can be used on any terminal or remote connection like SSH 

uses `pcap` and `libpcap` to capture traffic from off the wire  
paired with interface set to promiscuous mode  
allows to listen for packets sourcing from or destined to any device in the LAN 

requires root or admin perms because of direct access to hardware 

locate tcpdump installation: 

![](../Images/Pasted%20image%2020231215163720.png)

verify version:

![](../Images/Pasted%20image%2020231215163801.png)

### Traffic captures with tcpdump

basic commands: 
- `D` = display any interfaces available to capture from 
- `i` = select interface to capture from 
- `n` = do not resolve hostnames
- `nn` = no hostnames or well-known ports
- `e` = grab ethernet header along with upper-layer data
- `X` = show contents of packets in hex and ASCII
- `XX` = same as X but will also specify ethernet headers (`Xe`)
- `v`, `vv`, `vvv` = increase verbosity
- `c` = grab specific number of packets then stop 
- `s` = defines how much of a packet to grap
- `S` = change relative sequence of numbers in the capture to display to absolute sequence numbers (13248765839 instead of 101)
- `q` = print less protocol information
- `r file.pcap` = read from file 
- `w file.pcap` = write into a file 

listing available interfaces: 

![](../Images/Pasted%20image%2020231215203838.png)

start capture packet by choosing interface: 

![](../Images/Pasted%20image%2020231215203950.png)

disable domain resolution and common port resolution: 

![](../Images/Pasted%20image%2020231215204158.png)

display ethernet header, which will change first line to show source MAC address of the host: 

![](../Images/Pasted%20image%2020231215204505.png)

show contents of packets in hex and the corresponding ASCII text: 

![](../Images/Pasted%20image%2020231215204802.png)

combination of commands: 

![](../Images/Pasted%20image%2020231215204943.png)

in the above command we: 
- disabled domain and port resolution
- specified verbosity 
- showed details of packet in ASCII/hex and displayed ethernet header

the typical output order is: 
- timestamp
- protocol + source/dest IP.port
	- protocol is upper-layer header, ex: IP
- flags being used such as SYN 
- sequence and acknowledgement numbers 
- protocol options
	- window size 
	- selective acknowledgements
	- window scale factors 
	- etc. 
- notes / next header
	- could see more header info since the packets are encapsulated 

### File I/O

`-w` to capture traffic to file  
can quickly use up open disk space and run into storage issues 

writing to file: 

![](../Images/Pasted%20image%2020231215211403.png)

reading from file: 

![](../Images/Pasted%20image%2020231215211435.png)

## Fundamentals Lab

Validate tcpdump is installed on the machine: 

![](../Images/Pasted%20image%2020231216190321.png)

view available interfaces to capture from: 

![](../Images/Pasted%20image%2020231216190413.png)

start a capture: 

![](../Images/Pasted%20image%2020231216190444.png)

modify capture to add verbosity and display contents in ASCII and hex: 

![](../Images/Pasted%20image%2020231216190602.png)

disable name resolution and display relative sequence numbers: 

![](../Images/Pasted%20image%2020231216190753.png)

save a capture to a pcap file: 

![](../Images/Pasted%20image%2020231216190920.png)

read a capture from a file:

![](../Images/Pasted%20image%2020231216190945.png)


