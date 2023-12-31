
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

