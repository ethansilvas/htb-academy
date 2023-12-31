
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


