
## Web Fuzzing 

`ffuf` and tools like it give us a way to automatically fuzz websites components or a web page 

one option is to fuzz for directories  
say we visit a site with no other information that can lead us to other pages, our only option is to fuzz the site to find other pages within it 

**fuzzing** = testing technique that sends various types of user input to an interface to see how it reacts 

sql injection fuzzing = send random special characters  
buffer overflow fuzzing = send long strings and incrementing length to see if and when the binary would break 

typically use pre-defined wordlists of commonly used terms for each type of fuzzing 

### Wordlists 

for determining which pages exist, we will need a wordlist with commonly used words for directories or pages 

SecLists has a useful directory list called `/Discovery/Web-content/directory-list-2.3-small.txt`

## Directory Fuzzing 

to begin with ffuf there are options to specify our wordlist and url

we can assign a wordlist to a keyword rather than the full path  
here we assign a path to a wordlist to `:FUZZ`: 

`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ`

then we can use :FUZZ where we want ffuf to check for directories in the target url: 

```shell
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ
```

ffuf can fuzz these urls very quickly but if we want to go even faster we can increase the number of threads being used: 

`-t 200` = number of threads to 200

however, this isn't recommended because this can disrupt the site causing a DoS or possibly even bring down your own internet 

### Finding more hidden directories

with our target IP and port we see a blank home page: 

![](../Images/Pasted%20image%2020231230164754.png)

now lets form a ffuf command to find hidden directories: 

![](../Images/Pasted%20image%2020231230165118.png)

this command will result in finding the URLs `forum` and `blog` which are both seemingly empty but do not return a 404 or error: 

![](../Images/Pasted%20image%2020231230165713.png)

![](../Images/Pasted%20image%2020231230165651.png)

## Page Fuzzing 

now that we've found hidden directories, we want to find more hidden pages within them  
we will use fuzzing again but first we will want to know what kinds of pages the site is using, such as html, aspx, php, etc. 

one common way to determine these extensions are by using the HTTP response headers and guessing  
for example, apache servers could be php, or IIS could be asp/aspx, etc. 

looking at the response headers would be time consuming so we can again use ffuf to fuzz the extensions 

we can use another wordlist to find extensions like: 

`ffuf -w /opt/useful/SecList/Discovery/Web-Content/web-extensions.txt:FUZZ`  

however, we will also need to know the name of the file that we are trying to find the extension for  
we can always just use two wordlists and have a unique keyword for each to do `FUZZ_1.FUZZ.2` to find both the file name and the extension  

but there is almost always find a `index.*` file in websites, so it is good to look for this one 

now we can use this command to find the file extension (note that web-extensions.txt contains the "." so we don't need to include in our command): 

```shell 
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
```

### Page fuzzing 

now that we have the general extension that can be used, we can use it to find more pages: 

`ffuf -w ... -u http://SERVER_IP:PORT/blog/FUZZ.php`

this will return results that if the status is 200 you can see the `size` parameter which will determine if the page is empty or has content within it 

### Fuzzing the blog directory 

now we want to use extension and page directories to find a flag hidden in one of the /blog pages 

first lets fuzz the extension of the /blog pages: 

![](../Images/Pasted%20image%2020231230173109.png)

now we know that the pages have the .php extension so now lets fuzz for pages under the /blog directory: 

![](../Images/Pasted%20image%2020231230173833.png)

since /blog/home is the only one that has a size over 0 I go there and the flag is in the page content 

## Recursive Fuzzing 

so far we have fuzzed for directories, gone under those directories and fuzzed for files/extensions  
however if we did this for dozens of directories this would take forever  

recursive fuzzing = auto scans under newly found directories 

some sites may have really long directory trees like /login/user/content/uploads/...   
this is why it is advised to specify a depth to our scan 

`-recursion` = enable recursive scanning 
`-recursion-depth` = specify the depth
`-e .php` = when using recursion we can specify the extension 
`-v` = output full URLs 

a full command similar to what we did previously would look like: 

```shell
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
```

using this on the spawned target reveals a flag in the forum directory: 

![](../Images/Pasted%20image%2020231230191218.png)

## DNS Records

many websites are not public websites reachable by anyone  
browsers only know how to go to IP addresses  
when you provide the browser a URL, it tries to map the URL to an IP with either the local `/etc/hosts` file and the public DNS  
if the url is not in either of those then it would not know how to connect to the site 

in the previous examples we found a page that said it was an admin panel that was moved to `http://academy.htb:PORT`, but when we try to visit it, it does not work 

to connecto to academy.htb we need to add it to our /etc/hosts file: 

`sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'`

if we use this command then we can go to our desired site and specify the port to get a response: 

![](../Images/Pasted%20image%2020231230201621.png)

however, this page is the same as the one when we go to the IP directly: 

![](../Images/Pasted%20image%2020231230201757.png)

so this means that academy.htb is the same domain as the ones we have been using in our testing so far  

and to confirm this we can try some of the other domains we found like /blog/index.php: 

![](../Images/Pasted%20image%2020231230201902.png)

in our earlier scans we did not find any mention of admin or panels, and the admin page found when going directly to the IP noted that the admin page was moved to academy.htb  

so this means we can now start looking for sub domains under `*academy.htb`

## Sub-domain Fuzzing

sub domains are any website underlying another domain  
photos.google.com is the photos sub-domain of google.com   
the concept is similar since we are just trying different websites to see if they exist  
all we need is a wordlist and target  

in SecLists, there is a list for sub-domains `/opt/useful/SecLists/Discovery/DNS/` 

our ffuf command is similar and we just need to change where we place our FUZZ keyword: 

`ffuf -w ... -u https://FUZZ.inlanefrieght.com/`

if we do these commands and we get 0 results then there are no sub-domains?  
no, this only means there are no public sub-domains 

even if we did the previous step of adding a domain like `academy.htb` to our /etc/hosts list, we only added the main domain   
so when ffuf looks for sub-domains it will not find them in the /etc/hosts list and instead looks for public DNS results  

here I can try to fuzz for sub-domains on inlanefreight: 

![](../Images/Pasted%20image%2020231231141641.png)

## Vhost Fuzzing 

previously we saw that we can fuzz public domains, but not private ones 

vhost = basically a sub-domain served on the same server and has the same IP, meaning a single IP could be serving two or more different sites  
vhosts may or may not have public DNS records 

vhost fuzzing = running a scan on an IP that we have identified, which will be able to find public and non-public sub-domains and vhosts 

to scan vhosts you could manually add an entire wordlist to our /etc/hosts, but obviously this is impractical  
instead we can fuzz HTTP headers, specifically the `Host:` header 

we can use the `-H` flag and use the FUZZ keyword within it: 

`ffuf -w ...subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'`

ffuf could return many results that all show 200 OK, but this is because we are simply changing the header while visiting academy.htb:PORT/, which we already know will return 200 OK  
if the vhost does exist then we should get a different response size because we would be getting the hidden page which is likely to have different content  

