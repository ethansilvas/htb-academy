
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

save a capture file either through the `File` dropdown or with the save capture toolbar button: 

![](../Images/Pasted%20image%2020231220191813.png)

capture filters are initiated before the capture starts, and display filters are used after the capture is complete 

wireshark does have trouble with large captures so the more specific the filters the better

#### Capture filters

before the capture starts  
use BPF syntax like `host 215.15.2.30`  

common filters: 
- `host` = only traffic pertaining to certain host 
- `net` = to or from a specific network, using / notation 
- `src/dst [host|net|port]` = specify traffic coming from or going to a specified entity
- `port` = capture from a specific port 
- `not port` = everything except a port 
- `port # and #` = get two different ports
- `portrange x-x` = all ports within a range 
- `ip / ether / tcp` = specified protocol headers
- `broadcast / multicast / unicast` = one to one, one to many, or one to all 

there are built in capture filters: 

![](../Images/Pasted%20image%2020231220193323.png)

we can then use these filters in the capture options menu: 

![](../Images/Pasted%20image%2020231220193503.png)

#### Display filters

used while the capture is running and after it has stopped 

proprietary to wireshark so there are more options than BPF 

common display filters: 
- `ip.addr = x.x.x.x` = only traffic from specific host 
- `ip.addr = x.x.x.x/24` = only traffic from a network 
- `ip.src/dst = x.x.x.x` = capture to or from a specific host
- `dns / tcp / ftp / arp / ip` = filter by protocol 
- `tcp.port == x` = filter by a tcp port
- `tcp.port / udp.port != x` = everything except specified port 
- `and / or / not` = and will concat, or will find either, not will exclude 

display filters can be added with the main dropdown: 

![](../Images/Pasted%20image%2020231220194136.png)

capture traffic from a specific host: 

![](../Images/Pasted%20image%2020231220194354.png)

keep in mind that for both capture and display filters that they are taken in a literal sense, so looking for port 80 traffic is not the same as looking for HTTP traffic  
ports can be bound and used for different purposes and looking for HTTP looks for key markers that the protocol uses such as GET/POST requests

## Familiarity With Wireshark 

a user has brought in a laptop with issues of network slowness, we connect laptop to network and perform packet captures to verify that the pc is working correctly 

### Task 1: Validate Wireshark is installed:

![](../Images/Pasted%20image%2020231220200631.png)

![](../Images/Pasted%20image%2020231220200651.png)

### Task 2/3: Select an interface to run a capture on and create a capture filter to only show traffic from your host IP 

![](../Images/Pasted%20image%2020231220201051.png)

### Task 4: Navigate to a webpage to generate traffic 

starting a capture and visiting pepsi.com (45.60.75.51) and using a display filter to find the start of the TCP connection: 

![](../Images/Pasted%20image%2020231220203510.png)

viewing all traffic related to pepsi.com: 

![](../Images/Pasted%20image%2020231220203719.png)

## Wireshark Advanced Usage

### Plugins 

the `Statistics` and `Analyze` tabs can provide many insights into our data  
can use many of the baked in plugins that wireshark has for detailed reports about network traffic  
can show top talkers in traffic, specific convos, breakdown by IP and protocol, etc. 

#### Statistics 

http packet counter: 

![](../Images/Pasted%20image%2020231221140115.png)

dns stats: 

![](../Images/Pasted%20image%2020231221140431.png)

generate traffic to duckduckgo.com (52.250.42.157), then view in the conversations stats: 

![](../Images/Pasted%20image%2020231221140724.png)

#### Analyze 

allows the following of tcp streams by stitching tcp packets back together to recreate the entire stream in a readable format 

finding a packet related to the duckduckgo IP address and following the stream: 

![](../Images/Pasted%20image%2020231221143102.png)

![](../Images/Pasted%20image%2020231221143141.png)

you can alternatively do this by entering a display filter for `tcp.stream eq #` where the # is the tcp stream index which you can find in the TCP info section: 

![](../Images/Pasted%20image%2020231221143537.png)

### Specific TCP streams 

wireshark can recover many types of data from streams, but it requires you to have captured the entire conversation 

can extract files from the object export option: 

![](../Images/Pasted%20image%2020231221144650.png)

![](../Images/Pasted%20image%2020231221144747.png)

FTP moves data between a server and host to pull it out of the raw bytes and reconstruct the file 

ftp uses port 20 and 21 to function  
20 = transfer data between server and host  
21 = ftp control port, any commands such as login, listing files, and issuing download/uploads 

useful FTP display filters:
- `ftp` 
- `ftp.request.command` = show any commands sent across the ftp-control channel, port 21
	- can look for info like usernames and passwords with this filter, and filenames
- `ftp-data` = show any data transferred over the data channel port 20
	- capture anything sent during the conversation, can reconstruct data by placing the raw data back into a new file and naming it properly 

also, since FTP uses TCP, we can still use the follow tcp stream to group conversations 

basic steps to dissecting ftp data: 
1. filter for FTP traffic with `ftp` 
2. look at command controls with `ftp.request.command`
3. choose a file then filter for `ftp-data`, select a packet that corresponds with our file and follow the tcp stream 
4. change show and save data as to Raw and save the content as the original file name 

## Packet Inception, Dissecting Network Traffic with Wireshark 

provided a packet capture with unencrypted web session data, there is an image embedded that needs to be used as evidence of bad network usage  
this image is believed to be sending messages hidden behind it  
use wireshark to locate and extract the evidence

### Task 1: Load the predefined pcap file:

![](../Images/Pasted%20image%2020231221172433.png)

### Task 2: Filter the results

our goal is to extract potential images embedded for evidence 

first apply a filter to view only http traffic:

![](../Images/Pasted%20image%2020231221172741.png)

### Task 3: Follow the stream and extract the item found

from the HTTP packets we can see that many files are being requested and there are several 200 OK responses for them: 

![](../Images/Pasted%20image%2020231221172907.png)

now using the tcp stream follow on one of the 200 OK responses we can see if any data has been transfered: 

![](../Images/Pasted%20image%2020231221173425.png)

we see that there are some images being sent in the JFIF format, so now we can create a display filter to see all HTTP traffic that includes JFIF images: 

![](../Images/Pasted%20image%2020231221173604.png)

with `File -> export objects -> http` we can then export/save all of the found image files: 

![](../Images/Pasted%20image%2020231221173743.png)

we know have all of the images that were requested: 

![](../Images/Pasted%20image%2020231221173939.png)

### Live capture and analysis 

after RDP'ing to a machine and performing a live capture, here are the results: 

![](../Images/Pasted%20image%2020231221180256.png)

before doing any specific analysis steps, lets do some general analysis tasks  
we are concerned with the two hosts 172.16.10.2 (our machine) and 172.16.10.20

right away we can see the two hosts forming a TCP connection: 

![](../Images/Pasted%20image%2020231221180736.png)

performing a tcp stream follow we get the following results: 

![](../Images/Pasted%20image%2020231221180859.png)

from the above results and a look at the packet info of the full conversation we can see some FTP traffic on port 21: 

![](../Images/Pasted%20image%2020231221181029.png)

doing a display filter for both of the IP addresses in question reveals that this was not the only connection the two formed: 

![](../Images/Pasted%20image%2020231221181806.png)

there are many packets being sent between the two hosts but from the above picture we can see some ftp-data traffic and HTTP traffic 

looking at the ftp-data traffic we can see the high ports being used line up with the previous info of the connection being in PASV mode: 

![](../Images/Pasted%20image%2020231221182101.png)

from the HTTP traffic we can see some php files being requested with 200 OK responses: 

![](../Images/Pasted%20image%2020231221182209.png)

it appears that our machine did a POST request on the login form: 

![](../Images/Pasted%20image%2020231221182510.png)

finally, looking at the `ftp.request.command` packets we can confirm some of the earlier found conversation: 

![](../Images/Pasted%20image%2020231221182851.png)

in this conversation, our host did the following:
- request to login as the user anonymous 
- check the OS 
- look at the current working directory
- change the file type to image
- get the size of a notable file named flag.jpeg
- switch to passive mode
- retrieve the flag.jpeg file 
#### FTP analysis 

so now that we know there is FTP traffic with a notable file named flag.jpeg, lets reassemble the ftp-data on our machine  

first lets look at the tcp stream related to the file in question and then save the data as raw: 

![](../Images/Pasted%20image%2020231221185005.png)

then after saving as the original file name, "flag.jpeg  

first lets look at the tcp stream related to the file in question and then save the data as raw: 

![](../Images/Pasted%20image%2020231221185005.png)

then after saving as the original file name, "flag.jpeg  

first lets look at the tcp stream related to the file in question and then save the data as raw: 

![](../Images/Pasted%20image%2020231221185005.png)

then after saving as the original file name, "flag.jpeg", we can see it in our system: 

![](../Images/Pasted%20image%2020231221185146.png)

#### HTTP analysis 

now lets go back to the HTTP traffic we saw and analyze it further

![](../Images/Pasted%20image%2020231221185426.png)

who is the webserver in question? 

172.16.10.20

what application is running the webserver? 

apache ubuntu: 

![](../Images/Pasted%20image%2020231221185654.png)

what were the most common method requests? 

lots of GET requests for pages and one POST for the login page 

following the HTTP stream we can see the POST request has a cleartext password in it: 

![](../Images/Pasted%20image%2020231221190112.png)

## Traffic Analysis Workflow 

### Analysis

#### What is the issue? 

unknown connections are making strange traffic to our hosts with a destination port that is uncommon and likely for malicious purposes 
#### Define our scope and goal

- What are we looking for? 
	- We are looking for any possible malicious activity related to the unknown host: 10.129.43.29 
- When did the issue start? 
	- May 10, 2021 21:32:13.810650000 BST
#### Capture network traffic and identify required network traffic components 

the target unknown host successfully connected to tcp port 4444 on our target system:

![](../Images/Pasted%20image%2020231226183141.png)

port 4444 is an uncommon port that is often used for remote access trojans or backdoors

the above conversation is the only conversation between the potential threat and our host  
following the tcp stream we can see some very harmful activity:

![](../Images/Pasted%20image%2020231226183559.png)

the stream reveals that after connecting to the target system the threat actor conducted some movement on the system then eventually created a new user `hacker`, then added that user to the admin group: 

![](../Images/Pasted%20image%2020231226183739.png)

## Decrypting RDP Connections 

when performing analysis of the target machine, some RDP traffic has been captured  
an RDP-key was found hidden in a folder hive on the target  
this key can be used to decrypt the communications between the target machine and a suspicious host 

### Analysis

first, lets filter to see all of the RDP traffic: 

![](../Images/Pasted%20image%2020231226194201.png)

for now, we can't see much because RDP uses TLS to encrypt any data transferred

filtering for port 3389 will give a better view on the connection: 

![](../Images/Pasted%20image%2020231226200654.png)

add the RSA key to the TLS options: 

![](../Images/Pasted%20image%2020231226201019.png)

now after filtering for RDP traffic we see all of the data traffic: 

![](../Images/Pasted%20image%2020231226201106.png)

we can see this traffic because we have the RDP certificate from the server, and OpenSSL can pull the private key from it 

### Viewing the encrypted traffic 

What host initiated the RDP session with our server? 

![](../Images/Pasted%20image%2020231226201708.png)

Which user account was used to initiated the RDP connection? 

from the RDP and TCP stream info we can see the user bucky was used: 

![](../Images/Pasted%20image%2020231226202658.png)


