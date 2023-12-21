
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

## Tcpdump Packet Filtering 

parse data included in our captures   

help reduce space needed to write the file and help buffer process data quicker   

filters will inspect any packets and look for given values in the protocol header to match 

most common filters: 
- `host` - anything involving the designated host (bidirectional) 
- `src / dest` - modifiers; designate source and dest host or port 
- `net` - show any traffic sourcing from or destined to the network designated; uses / notation
- `proto` - filter for a specific proto type  
- `portrange` - range of ports (0-1024) 
- `less / greater "<>"` - look for a packet or protocol option of a specific size 
- `and / &&` - concatenate two different filters together; ex: host AND port 
- `or` - match either of two conditions 
- `not`- anything but x 

host filter to look for only activity from specific host: 

![](../Images/Pasted%20image%2020231218185546.png)

source and destination filters can be specified for hosts, network ranges, and ports:
`src/dst [host|net|port] [IP|Network Range|Port]` 

source to filter for traffic originating from a specified host IP: 

![](../Images/Pasted%20image%2020231218190754.png)

using source with port number to find all traffic where the source port is HTTP: 

![](../Images/Pasted%20image%2020231218191411.png)

using destination to filter for traffic going to a specified network range

![](../Images/Pasted%20image%2020231218192602.png)

when specifying protocols you can use the common name (tcp, udp, icmp...) or use their respective protocol numbers:

![](../Images/Pasted%20image%2020231218192939.png)

![](../Images/Pasted%20image%2020231218193016.png)

protocol 17 is udp so the previous two commands are the same  
using `proto` will be more useful when starting to dissect specific part of the IP or other protocol headers  

keep in mind that port numbers can be used for anything  
so if we really want to only see HTTP traffic we need to specify protocol and port like `tcp port 80`

for protocols that use both tcp and udp like DNS we can filter looking at one or the other 

for ports, we can also look at a range of ports with `portrange`: 

![](../Images/Pasted%20image%2020231218194506.png)

using `less` or `greater` (or `<>`) we can look for traffic based on the packet size  

look for packets that are less than 64 bytes:

![](../Images/Pasted%20image%2020231218200657.png)

using greater to find packets greater than 500 bytes: 

![](../Images/Pasted%20image%2020231218201108.png)

`AND` will show us anything that meet both requirements 

capture any traffic from a specific host and on port 23:

![](../Images/Pasted%20image%2020231218220911.png)

using the or filter to view ICMP traffic or traffic from a specified host:

![](../Images/Pasted%20image%2020231218221113.png)

use not fijlter to get all traffic that isn't ICMP: 

![](../Images/Pasted%20image%2020231218221322.png)

### Pre-capture filters vs post-capture processing  

can either apply filters to capture directly or when reading a pcap file  
reading from file will not alter file

### Tips and tricks

`-S` will show absolute sequence numbers which are harder to read but if we look for these values in another log or tool we will only be able to find the packet based on absolute sequence numbers

`-v -X -e` can help increase the amount of data captured while `-c -n -s -S -q` can help reduce and modify the amount of data written or seen 

`-A` will show only ASCII text after the packet line instead of both ASCII and hex  
`-l` will tell it to output packets in a different mode; line buffer instead of pooling and pushing in chunks

`sudo tcpdump -Ar telnet.pcap` - will help you quickly look for anything human readable in the output 

`sudo tcpdump -Ar http.cap -l | grep 'mailto:*'` - using -l will let you pipe out the output to another command  
can be a quick way to scrape websites for email addresses, naming standards, and more 

will need a little bit of knowledge on how protocols are structured to dig deeper into packets  
here we look for the 13th byte in the structure and the 2nd bit:

`sudo tcpdump -i eth0 'tcp[13] &2 != 0'` 

## Interrogating Network Traffic With Capture and Display Filters

this lab will explore network traffic using packet filters to find more and more specific results

the goal will be to determine what servers are answering DNS and HTTP/S requests in our local network 

### Task 1: Read capture file without filters

![](../Images/Pasted%20image%2020231219132210.png)

### Task 2: Identify the type of traffic seen

Common protocols: 
- mixture of tcp and udp 
- HTTP/S 
- DNS 

Ports utilized: 
- 80, 443, 53 (DNS)
- 50296
- 40000
- 37106
- 56302
- 52540
- 52542

### Task 3: Identify conversations

What are the client and server port numbers of the first full TCP handshake?

client = 43806 (and other high ports for comms)
server = 80, 443

![](../Images/Pasted%20image%2020231219133823.png)

Who are the severs in these conversations?

- static.30.26.216.95.clients.your-server.de
- atl26s18-in-f10.1e100.net

![](../Images/Pasted%20image%2020231219134123.png)

Who are the receiving hosts? 

172.16.146.2

### Task 4: Interpret the capture in depth

What is the timestamp of the first established conversation in the pcap? 

16:34:01.401270

What is the IP address of apache.org from the DNS server responses? 

![](../Images/Pasted%20image%2020231219140351.png)

What protocol is being used in the first conversation? 

HTTP port 80

### Task 5: Filter out traffic

Filter out traffic that is not DNS:

![](../Images/Pasted%20image%2020231219141601.png)

Who is the DNS server for this segment? 

172.16.146.1

What domain names were requested in the pcap file? 

- apache 
- google fonts 
- youtube
- ocsp 
- google apis

What type of DNS records could be seen? 

- IPv4 A
- IPv6 AAAA
- CNAME

Who requests an A record for apache.org? 

![](../Images/Pasted%20image%2020231219142108.png)

What information does an A record provide? 

IPv4 address

### Task 6: Filter for TCP traffic

Filter to only see HTTP/S traffic: 

![](../Images/Pasted%20image%2020231219143410.png)

What are the most common HTTP request methods from this pcap? 

POST

![](../Images/Pasted%20image%2020231219144019.png)

What is the most common HTTP response from this pcap? 

200

![](../Images/Pasted%20image%2020231219144355.png)

### Task 7: What can you determine about the server in the first conversation

host = 172.16.146.2  
server = static.30.26.216.95.clients.your-server.de

![](../Images/Pasted%20image%2020231219150854.png)

## Analysis With Wireshark 

wireshark is GUI network traffic analyzer  
can capture data off many different interfaces, even USB or bluetooth  
provides much better deep packet analysis  

features and capabilities: 
- deep packet inspection 
- graphical and TTY interfaces
- can run on most OS 
- ethernet, IEEE 802.11, PPP/HDLC, ATM, bluetooth, usb, token ring, frame relay, ... 
- decryption capabilities for IPsec, ISAKMP, Kerberos, snmpv3, ssl/tls, wep, wpa/wpa2, ... 

can check for wireshark with `which wireshark` and install with `sudo apt install wireshark`

### TShark vs wireshark (terminal vs GUI)

TShark = terminal tool based on wireshark  
good for machines with little to no desktop environment  
can easily pass captures to other tools  

wireshark = feature rich GUI option for packet captures and analysis 

basic tshark switches: 
- `D` = display any interfaces available to capture from then exit out 
- `L` = list the link-layer mediums you can capture from and then exit out (ethernet as ex)
- `i` = choose interface to capture from 
- `f` = packet filter in libpcap syntax; used in direct capture 
- `c` = get specific number of packets
- `a` = autostop condition; can be after duration, file size, or certain number of packets 
- `r` = read from pcap file 
- `W` = write into a file using pcapng format 
- `P` = print the packet summary while writing to a file
- `x` = add hex and ascii output into the capture 
- `h` = see help menu 

### Tshark basic usage

showing interfaces available to capture from: 

![](../Images/Pasted%20image%2020231219205924.png)

basic packet capture: 

![](../Images/Pasted%20image%2020231219210153.png)

write to a capture file:

![](../Images/Pasted%20image%2020231219210429.png)

read from the capture file:

![](../Images/Pasted%20image%2020231219210508.png)

applying filters with `-f`:

![](../Images/Pasted%20image%2020231219212326.png)

### Termshark

text based UI app that provides wireshark-like interface in your terminal window

need to install from github 

### Wireshark GUI walkthrough 

3 main panels
- packet list
- packet details
- packet bytes

shows packet encapsulation in reverse order with lower layers encapsulation at the top of the window and higher levels at the bottom  
ex: 
- frame 4
- ethernet
- internet
- HTTP

packet bytes shows contents in ascii or hex 

### Packet captures with Wireshark

can start a capture either using the big blue fin icon to start a quick capture or by going into `Capture -> options -> select interface -> start`

![](../Images/Pasted%20image%2020231220173145.png)

one thing to note is that any changes in the capture options will restart the trace 

### The basics

