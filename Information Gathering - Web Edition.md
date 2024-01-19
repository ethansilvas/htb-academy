
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