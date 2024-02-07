# Information Gathering - Web Edition

## Information Gathering 

info gathering = first step in every pen test where we are simulating attackers with no internal info 

![](Images/Pasted%20image%2020240119122721.png)

understand the attack surface, tech used, and sometimes development environments or unmaintained infrastructure 

iterative process; as we discover assets we need to fingerprint the tech being used, look for hidden pages, etc.   
these may lead us to another asset where we repeat the process

subdomains and vhosts typically have different tech used than the main site because they are used to present other info and perform other tasks 

want to identify as much info as we can about these areas: 
- domains and subdomains - many orgs often do not have accurate asset inventory and might forget domains and subdomains exposed externally. 
- ip ranges - may lead to finding other domains and subdomains 
- infrastructure - what tech stacks our target is using. Are they using ASP.NET, Django, PHP, ... What type of APIs or web services are they using? Are content management systems like wordpress being used? What web server is being used? What back end databases are being used? 
- virtual hosts - indicate that multiple applications are being hosted on the same web server 

information gathering can be broken down to two main categories: 
- passive info gathering - do not interact directly with target. Collect publicly available info with search engines, whois, certificate info, etc. 
- active info gathering - directly interact with the target. Port scanning, DNS enumeration, directory brute-forcing, vhost enumeration, and web app crawling/scanning

crucial to keep the info that we collect well documented to include in our report or proof of concept 

## WHOIS

WHOIS is like the white pages for domain names  
TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default  
use it for querying databases containing domain names, IP addresses, or autonomous systems 

domain lookups retrieve info about the domain name of an already registered domain   
internet corporation of assigned names and numbers (ICANN) requires that registrars enter the holder's contact info, domain creation, and expiration dates, and other info 

sysinternals WHOIS = windows
WHOIS = linux 
whois.domaintools online 

a simple command will result in a lot of info: 

![](Images/Pasted%20image%2020240119131007.png)

we could do the same on windows with `whois.exe facebook.com`

## DNS 

now that we have some info about our target we can start looking further into it to identify particular targets, and the DNS is a good place to look 

### What is DNS? 

is like the internet's phonebook   
domain names allow people to access content on the internet  
IP addresses are used to communicate between web browsers  
DNS converts domain names to IP addresses, allowing browsers to access resources on the internet 

each internet-connected device has a unique IP that other machines use to locate it  

some benefits: 
- can remap the name to a new IP address instead of people needing to know the new IP 
- a single name can refer to several hosts splitting the workload between different servers 

there is a hierarchy of names in the DNS structure   
system's root, or the highest level, is unnamed 


TLDs nameservers = Top-level domains  
like a single shelf of books in a library  
last portion of a hostname is hosted by TLD nameserver   
ex: `facebook.com` TLD server is `com`   
most are associated with a specific country or region   
there are also generic top level domains gTLDs that aren't associated with country or region  
TLD managers have responsibility for procedures and policies for the assignment of second level domain names SLDs and lower level hierarchies of names  

resource records are the result of DNS queries and have this structure: 
- resource record - a domain name, usually a FQDN, if not then the zone's name where the record is located will be appended to the end of the name 
- TTL - in seconds; defaults to min value specified in the SOA record 
- record class - Internet, Hesiod, or Chaos 
- start of authority SOA - first in a zone file because it is start of a zone. Each zone can only have one SOA record and contains the zone's values like serial number and multiple expiration timeouts 
- name servers NS - the distributed database is bound together by NS records. In charge of zone's authoritative name server and the authority for a child zone to a name server
- IPv4 Addresses (A) - mapping between a hostname and an IP address. Forward zones are those with A record
- pointer PTR - mapping between an IP address and a hostname. Reverse zones are those that have PTR records 
- canonical name CNAME - alias hostname is mapped to an A record hostname using CNAME record
- mail exchange MX - identifies a host that will accept emails for a specific host. Priority value assigned to specified host. 

### Nslookup and DIG 

need to find an org's infrastructure and identify which hosts are publicly accessible   

nslookup can search for domain name servers and ask about info on their hosts and domains  

we can query A records by using a domain name, but we can also use `-query` parameter to search specific resource records 

here we query an A record: 

![](Images/Pasted%20image%2020240119135434.png)

we can also specify a nameserver by adding `@<nameserver/IP>` 

DIG shows us some more info that may be of use: 

![](Images/Pasted%20image%2020240119135642.png)

the entry above starts with the complete domain name   
it may be held in the cache for 20 seconds before the info needs to be requested again   
the class is in the Internet (IN)

now lets query for a specific subdomain: 

![](Images/Pasted%20image%2020240119140134.png)

![](Images/Pasted%20image%2020240119140200.png)

using the `-query` we can specify to look for pointer records: 

![](Images/Pasted%20image%2020240119140618.png)

we can do the same with DIG with the `-x` option: 

![](Images/Pasted%20image%2020240119140711.png)

we can use the keyword `ANY` to look for any existing records: 

`nslookup -query=ANY google.com`

and similarly with DIG: 

![](Images/Pasted%20image%2020240119142102.png)

RFC8482 specified that ANY DNS records be abolished so we might not get a response or if we do we might get a reference to RFC8482

we can use `TXT` to find TXT records: 

![](Images/Pasted%20image%2020240119142254.png)

and we can use `txt` in DIG: 

![](Images/Pasted%20image%2020240119142415.png)

these store text notes about the host or other names such as human readable info about a server, network, data center, etc. 

using `MX` we can look for mail servers: 

![](Images/Pasted%20image%2020240119142609.png)

same with DIG: 

![](Images/Pasted%20image%2020240119142634.png)

orgs are given IP addresses on the internet but they aren't always their owners  
ISPs and hosting services may leas smaller netblocks to them  

we can combine results from nslookup and WHOIS to see if our target has hosting providers: 

for some examples we can first find the IP address for inlanefreight: 

![](Images/Pasted%20image%2020240119143634.png)

now lets find the subdomain for 173.0.87.51:

![](Images/Pasted%20image%2020240119143701.png)

and the mailservers for paypal.com: 

![](Images/Pasted%20image%2020240119143724.png)

## Passive Subdomain Enumeration 

subdomain enumeration = mapping all available subdomains within a domain name  
increase attack surface and may uncover hidden management backend panels or intranet web apps   

### VirusTotal 

virustotal maintains a DNS replication service which is made by preserving DNS resolutions when users visit URLs given by them   

for info on a domain you can search for it and go to the `relations` tab: 

![](Images/Pasted%20image%2020240119165947.png)

### Certificates 

we can also get subdomains from SSL/TLS certificates because of Certificate Transparency (CT) which requires every SSL/TLS certificate issued by a CA to be published in a public log 

https://search.censys.io/

[https://crt.sh](https://crt.sh)

![](Images/Pasted%20image%2020240119170621.png)

we can use curl requests to easily work with the results: 

`curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"`

![](Images/Pasted%20image%2020240119171019.png)

we can also manually do this with OpenSSL: 

````shell
openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u
````

![](Images/Pasted%20image%2020240119171215.png)

### Automating passive subdomain enumeration 

TheHarvester is an early-stage pen testing tool   
can use it to gather info to help identify a company's attack surface   
collects emails, names, subdomains, IP addresses, URLs 

here are some useful modules: 

![](Images/Pasted%20image%2020240119171537.png)

we can create a text file with all of these: 

![](Images/Pasted%20image%2020240119175937.png)

then input them into the harvester: 

`cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done`

![](Images/Pasted%20image%2020240119180008.png)

you can then see all of the created files: 

![](Images/Pasted%20image%2020240119180106.png)

then we can extract all the subdomains from them: 

```shell
cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

we can then merge all the passive recon files with:

```shell
cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
cat facebook.com_subdomains_passive.txt | wc -l
```

![](Images/Pasted%20image%2020240119180234.png)

we can see that we found 9164 subdomains 

## Passive Infrastructure Identification 

netcraft can offer info about servers without interacting with them 

`https://sitereport.netcraft.com`

some results we are interested in are: 
- background - general info about domain and date it was first seen by netcraft crawlers
- network - info about the netblock owner, hosting company, nameservers, etc. 
- hosting history - latest IPs used, webserver, target OS 

![](Images/Pasted%20image%2020240119181801.png)

need to pay attention to the latest IPs used  
sometimes we can spot the IP address from the webserver before it was placed behind a load balancer, WAF, or IDS 

### Wayback machine

the internet archive provides access to digitalized materials like websites   

using the wayback machine we can access versions of these sites that could be old  
these sites may have interesting comments on their source code or files that shouldn't be there  

for example, we can find an older version of the site that uses an old plugin that is very vulnerable  
we might see on the current site that this plugin wasn't removed properly and can still be accessed via the wp-content directory 

![](Images/Pasted%20image%2020240119185037.png)

we can also use `waybackurls` to inspect urls saved by wayback machine and look for specific keywords: 

`go install github.com/tomnomnom/waybackurls@latest`

we can use the `-dates` switch to get a list of crawled URLs from a domain 

`waybackurls -dates https://facebook.com > waybackurls.txt`

## Active Infrastructure Identification 

infrastructure is what keeps the site running  
web servers are directly involved in operation - Apache, NGINX, Microsoft IIS, etc. 

if we can discover the web server then we can likely find the OS that the back-end server is running  
for example if we find out the IIS version being run then we can map it back to the windows version that it comes installed on by default   

### Web servers

some info we want to find about the web server: 
- url rewriting functionality 
- load balancing 
- script engines used
- IDS 

first thing we can do is look at the response headers: 

`curl -I <target>`

other characteristics to take into account of: 
- X-Powered-By header - can tell us what the web app is using (php, asp.net, jsp, etc.)
- cookies - each technology by default has its cookies 
	- .NET = `ASPSESSIONID<RANDOM>=<COOKIE_VALUE>`
	- PHP = `PHPSESSID=<COOKIE_VALUE>` 
	- JAVA = `JSESSION=<COOKIE_VALUE>`

automated tools often prob servers and compare their responses to guess info like version, installed modules, enabled services, ... 

`Whatweb` recognizes web technologies like CMS, blogging platforms, statistic/analytics packages, JS libraries, web servers, and embedded devices  

`Wappalyzer` is similar to whatweb but results are displayed while navigating the target url 

`WafW00f` is a WAF fingerprinting tool to determine if a security solution is in place 

`sudo apt install wafw00f -y`

we can use options like `-a` to check for all solutions in place instead of stopping on the first found one   
read targets from a file with `-i`  
or proxy the requests using `-p`

`wafw00f -v https://facebook.com`

`Aquatone` is for automatic and visual inspection of websites across hosts   
good for gaining overview of HTTP-based attack surfaces by scanning list of ports, visiting the site with a headless chrome browser, and taking a screenshot  

```shell
sudo apt install golang chromium-driver
go get github.com/michenriksen/aquatone
export "$PATH":"$HOME/go/bin"
```

we could cat our list of subdomains to aquatone with: 

`cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000`

for some examples on how to use these technologies, lets consider two vhosts: 
- app.inlanefreight.local
- dev.inlanefreight.local

what apache version is running on app.inlanefreight.local? which CMS is being used? 

for this we can simply run whatweb with an aggression level of 3: 

![](Images/Pasted%20image%2020240119205127.png)

which operating system is in the dev.inlanefreight.local webserver? 

now lets try visiting dev.inlanefreight.local and look with wappalyzer: 

![](Images/Pasted%20image%2020240119205543.png)

## Active Subdomain Enumeration 

can perform active subdomain enumeration by probing the infrastructure managed by the target or the 3rd party DNS servers we have identified   
keep in mind our traffic will be detected 

### ZoneTransfers 

zone transfer = secondary DNS server receives info from the primary DNS server and updates it   

[https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/)

we can use `zonetransfer.me` to view information we get from a zone transfer: 

![](Images/Pasted%20image%2020240120135408.png)

to do this manually we can do the following: 

identify nameservers: 

`nslookup -type=NS zonetransfer.me`

![](Images/Pasted%20image%2020240120135636.png)

then perform a zone transfer using `-type=any` and `-query=AXFR`: 

![](Images/Pasted%20image%2020240120135744.png)

in the results we can see a lot of subdomain information, and if the zonetransfer is successful then we don't need to do much more enumeration

![](Images/Pasted%20image%2020240120135852.png)

### Gobuster

tool for subdomain enumeration 

in our previous passive domain enumeration we saw patterns like `lert-api-shv-{number}-sin6.facebook.com` 

first lets use these patterns to create a text file: 

![](Images/Pasted%20image%2020240120140548.png)

next we can use gobuster with the following options: 
- `dns` - launch the DNS module 
- `-q` - don't print the banner 
- `-r` - use custom dns server
- `-d` - target domain name 
- `-p` - path to the patterns file 
- `-w` - path to the wordlist 
- `-o` - output file

````shell
gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
````

![](Images/Pasted%20image%2020240120141311.png)

first we enumerate all of the name servers that we want to test, then we can use `nslookup -query=AXFR <IP_ADDRESS> <NS_IP>` to look for any successful transfers on each of the found results to determine how many zones there are:

![](Images/Pasted%20image%2020240122123807.png)
## Virtual Hosts

vhost = allow several sites to be hosted on a single server   
ex: hosting a mobile and desktop version of the site on the same server 

two ways to configure vhosts: 
- IP-based virtual hosting
- name-based virtual hosting 

### IP-based virtual hosting

a host can have multiple NIC   
multiple IP addresses or interface aliases can be configured on each NIC of a host   
the servers or virtual servers bind to one or more IP addresses  
different servers can be addressed under different IP addresses on the same host  
from the client's pov the servers are independent of each other  

### Name-based virtual hosting 

the distinction for which domain the service was requested is made at application level  
this means that `admin.inlanefreight.htb` and `backup.inlanefreight.htb` can refer to the same IP   
internally on the server these are separated using different folders  

`admin.inlanefreight.htb` can point to `/var/www/admin` and `backup.inlanefreight.htb` can point to `/var/www/backup` 

in our testing we have seen domains having the same IP address that can be either vhosts or different servers hiding behind a proxy

if we've identified the IP `192.168.10.10` and it returns a default page when we make a request, we can further look for vhosts

we can request a domain we have previously found during our previous info gathering in the `Host` header: 

`curl -s http://192.168.10.10 -H "Host: randomtarget.com` 

we can then further automate this by using a dictionary file like `/opt/useful/SecLists/Discovery/DNS/namelist.txt`

```shell
cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done
```

we could then identify targets like `dev-admin.randomtarget.com`

### Automating vhost discovery 

we can use ffuf to fuzz the directories with a command like: 

`ffuf -w <wordlist>:FUZZ -u http://SERVER_IP -H "HOST: FUZZ.randomtarget.com" -fs <size>`

so now we can look at a given ip which returns a default page: 

![](Images/Pasted%20image%2020240122141625.png)

we can do some basic enumeration: 

![](Images/Pasted%20image%2020240122141836.png)

![](Images/Pasted%20image%2020240122142031.png)

we know that we want to fuzz `*.inlanefreight.htb` so lets set up our command: 

`ffuf -w /opt/useful/SecLists/Discovery/DNS/namelist.txt:FUZZ -u http://10.129.223.148 -H "HOST:FUZZ.inlanefreight.htb"`

![](Images/Pasted%20image%2020240122142558.png)

then after adding these to `/etc/hosts` I can make a curl request to see which ones return the flag: 

![](Images/Pasted%20image%2020240122142920.png)

## Crawling 

we use crawling to find as many pages and subdirectories as we can find 

zap spider only enumerates the resources it finds in links and forms (passive scan), but it can miss hidden folders and backup files 

we can use ffuf to find these: 

`ffuf -recursion -recursion-depth 1 -u http://SERVER_IP/FUZZ -w wordlist.txt:FUZZ`

### Sensitive information disclosure 

common to find backup or unreferenced files that can contain sensitive info  

some common extensions we can find in SecLists are in `raft-[small, med, large]-extensions.txt`

start by creating a list of folders we have found before: 

```
wp-admin
wp-content
wp-includes
```

then we can extract keywords from our target site using cewl  
we can tell it to extract words with a min of 5 chars `-m5`, convert them to lowercase `--lowercase`, and save them to file `-w <file>`

`cewl -m5 --lowercase -w wordlist.txt http://SERVER_IP`

then we can define multiple wordlists in ffuf: 

`ffuf -w folders.txt:FOLDERS, wordlist.txt:WORDLIST, extensions.txt:EXTENSIONS -u http://SERVER_IP/FOLDERS/WORDLISTEXTENSIONS`

## Information Gathering - Web - Skills Assessment 

perform passive and active information gathering against githubapp.com 

### What is the registrar IANA ID number

using WHOIS we can see that it is 292: 

![](Images/Pasted%20image%2020240122152557.png)

### What is the last mailserver returned when querying the MX records 

using dig I can see that it is aspmx5: 

![](Images/Pasted%20image%2020240122153731.png)

### Perform active infrastructure identification against i.imgur.com. What server name is returned for the host

for this we can use netcraft to see that it is cat factory 1.0: 

![](Images/Pasted%20image%2020240122154746.png)

### Perform subdomain enumeration against githubapp.com. Which subdomain has the word triage in the name

for this we can just reuse the following command to get the crt.sh results: 

`curl -s "https://crt.sh/?q=githubapp.com&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"`

![](Images/Pasted%20image%2020240122162900.png)


