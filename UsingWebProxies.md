# Using Web Proxies

## Intro to Web Proxies 

most web apps are continuously connecting to back-end servers to send and receive data  
testing and securing back-end servers is becoming more and more important 

testing back-end servers make up the bulk of web app pen testing   
to capture the requests and traffic passing between apps and back-end servers, and then manipulate them, we need to use web proxies 

**web proxies** are tools that can be setup between a browser/mobile app and a back-end server to capture and view all requests being made between them   
essentially a MITM tool   
packet sniffers like wiresharks work by analyzing all local traffic, where web proxies work with web ports like 80 and 443

they are essential tools for intercepting requests and modifying them to see how the back-end server handles them 

there are other uses than just HTTP requests: 
- web app vulnerability scanning 
- web fuzzing 
- web crawling 
- web app mapping 
- web request analysis 
- web configuration testing 
- code review 

### Burp suite

most common web proxy for web pen testing  
various features and built in chromium browser to test web apps  

paid only features: 
- active web app scanner
- fast burp intruder 
- ability to load certain burp extensions 

free version good enough for most pen testers  

### OWASP zed attack proxy (ZAP)

another common web proxy tool   
open-source and no paid only   
continually gaining many of the paid-only features that burp has   

## Setting up

after installed, burp can be launched as an app or through the terminal with `burpsuite`  
can also run the JAR file: 

`java -jar /burpsuite.jar`

when we open burp and are greeted with the project screen, if we are using the community version we would only be able to use temporary projects without being able to save them  

![](Images/Pasted%20image%2020240110140558.png)

then we will be prompted about configurations, there are either burp default configurations or you can load a config file 

ZAP also has the ability to be ran as an app or as a jar  
can also launch from terminal with `zaproxy`   

zap gives the option to save a project without paying, but for our purposes we will only need temp projects 

## Proxy Setup 

with burp and zap we can set them up as a proxy for any app so that all requests can be routed through them  

### Pre-configured browser 

first we need to configure our browser to use the tools as the proxy, or use the pre-configured browser  

in burp there is the option to open the pre-configured browser in the `Proxy -> Intercept` menu: 

![](Images/Pasted%20image%2020240110173618.png)

in ZAP there is a firefox button in the top toolbar: 

![](Images/Pasted%20image%2020240110174057.png)

### Proxy setup 

burp and zap use 8080 for the web proxy listening port by default  

if we wanted to serve the web proxy on a different port we can do so in burp under `Proxy -> Options` and in zap under `Tools -> Network -> Local Servers/Proxies` 

with the foxyproxy browser extension you can modify the different proxy IPs or ports you want to use: 

![](Images/Pasted%20image%2020240110174821.png)

### Installing CA certificate

with our browser we will need to install the web proxy's CA certificates so that all HTTPS traffic is properly routed  

you can get the burp certificate with the foxyproxy set and going to `http://burp`: 

![](Images/Pasted%20image%2020240110183038.png)

you can get them in zap by going to `Tools -> Network -> Server Certificates` 

![](Images/Pasted%20image%2020240110183320.png)

then with the certificates you can go to `about:preferences#privacy` in firefox and view your certificates

in the `Authorities` tab you can import the files downloaded from burp and zap: 

![](Images/Pasted%20image%2020240110183527.png)

now all firefox web traffic will start routing through our proxy 

## Intercepting Web Requests 

with our proxy in place we can intercept and manipulate HTTP requests sent by the web app  

### Intercepting requests 

with burp we go to the `Proxy` tab and make sure request interception is on  

after going to our spawned target we can see the request show up in burp: 

![](Images/Pasted%20image%2020240110191213.png)

since this acts as a MITM we can choose to forward or drop the request, forwarding it allows us to then load the site: 

![](Images/Pasted%20image%2020240110191250.png)

for zap, interception is off by default and we can enable it with the green button in the top bar: 

![](Images/Pasted%20image%2020240110191937.png)

then after visiting the site you can see the requests just like burp: 

![](Images/Pasted%20image%2020240110192029.png)

zap also inlcudes a HUD that is visible once we forward requests and view the site: 

![](Images/Pasted%20image%2020240110192210.png)

### Manipulating intercepted requests 

when we have captured requests we can manipulate them before we forward them to better understand how the site will react to any changes we make  

there are many applications in pen testing that make use of this: 
- SQL injections 
- command injections 
- upload bypass
- authentication bypass
- XSS
- XXE
- error handling 
- deserialization 

if we use the ping button to send another request and capture it: 

![](Images/Pasted%20image%2020240110193741.png)

![](Images/Pasted%20image%2020240110193729.png)

we can now manipulate the request to insert characters that would otherwise be blocked by the front-end protection code   
there still may be protections in the backend but we can check by manipulating the request before forwarding it 

if we replace the IP we provided with `;ls;` we can get the ls command response: 

![](Images/Pasted%20image%2020240110194038.png)

## Intercepting Responses

sometimes we may need to intercept the HTTP responses from the server before they reach the browser   
this can help us change how a web page looks, for example showing/hiding disabled fields 

### Burp 

enable response interception in `Proxy -> Options`: 

![](Images/Pasted%20image%2020240111154702.png)

we can then see the response we get after forwarding the ping button request like we did earlier: 

![](Images/Pasted%20image%2020240111154942.png)

lets try changing the input type to text instead of number and increase the maxlength to input bigger strings:  

![](Images/Pasted%20image%2020240111155054.png)

this then allows us to do the same exploit we did before, but through the UI: 

![](Images/Pasted%20image%2020240111155231.png)
![](Images/Pasted%20image%2020240111155258.png)

the same technique can be used to persistently enable any disabled HTML buttons 

### ZAP 

zap will automatically intercept the response for you to edit: 

![](Images/Pasted%20image%2020240111160326.png)

![](Images/Pasted%20image%2020240111160246.png)

another feature that the ZAP HUD has is to automatically show/hide any disabled or hidden fields: 

![](Images/Pasted%20image%2020240111160508.png)

burp also has these options in `Proxy -> Options -> Response Modification`: 

![](Images/Pasted%20image%2020240111160612.png)

you can also view any html comments in their position with the HUD: 

![](Images/Pasted%20image%2020240111160710.png)

## Automatic Modification 

we might want to apply mods to all outgoing HTTP requests or all incoming HTTP requests  

### Automatic request modification

we can choose to match any text within out requests, either in the header or body 

first lets replace our User-Agent with "HackTheBox Agent 1.0" 

for burp we can go to `Proxy -> Options -> Match and Replace`: 

![](Images/Pasted%20image%2020240111165141.png)

we can then revisit the page and notice the User-Agent header is changed with our value: 

![](Images/Pasted%20image%2020240111165259.png)

zap has a replacer feature that we can see by going to `Tools -> Replacer options`: 

![](Images/Pasted%20image%2020240111165721.png)

zap also has the request header string that we can use with a regex pattern: 

![](Images/Pasted%20image%2020240111170235.png)

### Automatic Response Modification

in the same menu for match and replace, we can create a rule for the response body: 

![](Images/Pasted%20image%2020240111172557.png)

this will automatically do our changes of swapping the form field from number to text

we can then see that these replacements were automatically applied to the response: 

![](Images/Pasted%20image%2020240111172649.png)

you can also apply the same rules using the zap replacer:

![](Images/Pasted%20image%2020240111173405.png)

then viewing the request and matching response you can see all the replacement rules applied: 

![](Images/Pasted%20image%2020240111173417.png)
![](Images/Pasted%20image%2020240111173433.png)

we can do the same with the request body to automatically apply our command injection: 

![](Images/Pasted%20image%2020240111173955.png)

![](Images/Pasted%20image%2020240111174043.png)

## Repeating Requests 

in the previous example of modifying a request and sending it, if we wanted to try multiple different commands the process would be very tedious  
we can use request repeating to make this faster 

request repeating lets us resend any web request that has previously gone through the proxy 

in burp we can see the proxy history in the `HTTP history` tab: 

![](Images/Pasted%20image%2020240111184416.png)

the zap history is at the bottom of the app: 

![](Images/Pasted%20image%2020240111184611.png)

these histories also maintain WebSockets history which shows all connections initiated by the web app even after being loaded, like async updates and data fetching 

zap only shows the final/modified request that was sent but burp you can see both the original and modified: 

![](Images/Pasted%20image%2020240111185123.png)

### Repeating requests 

right-clicking a request in burp will allow you to send the request to the repeater: 

![](Images/Pasted%20image%2020240111185217.png)

then you can navigate to the repeater tab: 

![](Images/Pasted%20image%2020240111185248.png)

right-clicking on the request again you can use the `Change request method` option to swap between GET and POST without having to rewrite the request: 

![](Images/Pasted%20image%2020240111185446.png)

in zap if you right click a request you can use the option `Open/Resend with request editor` to resend requests: 

![](Images/Pasted%20image%2020240111185607.png)

![](Images/Pasted%20image%2020240111185616.png)

there is also a method drop-down menu to swap HTTP methods: 

![](Images/Pasted%20image%2020240111185645.png)

using the repeater we can quickly try other commands to get the other flag: 

![](Images/Pasted%20image%2020240111191652.png)

## Encoding/Decoding

when we modify and send custom HTTP requests we might have to perform different types of encoding/decoding to interact with the webserver properly  

### URL encoding

it is essential to ensure that our request data is URL-encoded and our headers are correctly set, or we might get a server error   

some key characters to encode: 
- spaces - might indicate the end of request data if not encoded 
- `&` - otherwise interpreted as a parameter delimiter
- `#` - otherwise interpreted as a fragment identifier 

you can url encode characters in burp by right-clicking and using `Convert Selection -> URL -> URL -> encode key characters`: 

![](Images/Pasted%20image%2020240111194848.png)

zap will do all of the URL-encoding in the background before sending 

### Decoding 

it is very common for web apps to encode their data, so we want to be able to decode it to examine the original text 

some of the other types of encoders that these tools support: 
- html
- unicode
- base64
- ASCII hex

in the `Decoder` section of burp we can decode string of text: 

![](Images/Pasted%20image%2020240111195816.png)

you can also use the burp inspector to highlight and view decodings: 

![](Images/Pasted%20image%2020240111200030.png)

in zap you can go to the `Tools -> Encode/Decode/Hash` section to use the equivalent tools: 

![](Images/Pasted%20image%2020240111200231.png)

you can also customize your tabs to include specific encodings: 

![](Images/Pasted%20image%2020240111200331.png)

### Encoding 

in the example text we can see that it says `{"username":"guest", "is_admin":false}`  
we might want to test modifying it to see if it changes our privileges 

so now we can change the text to instead set is_admin to true and then get the proper encoding for it: 

![](Images/Pasted%20image%2020240111201130.png)

## Proxying Tools 

an important tool for proxies is enabling the interception of web requests made by cli tools and thick client apps  

to route all web requests made by these tools through our proxy we have to set them up as the tool's proxy, like `http://127.0.0.1:8080` with our browser  
each tool may have a different method for setting its proxy 

### Proxychains 

proxychains route all traffic coming from any command line to any proxy we specify  
proxychains adds a proxy to any cli tool and is the easiest method to route traffic through our proxies 

first we need to edit `/etc/proxychains.conf`, comment out the final line in the file and add this to the end: 

```shell
#socks4           127.0.0.1 9050
http 127.0.0.1 8080
```

might also want to enable quite mode by un-commenting `quiet_mode` 

then we can prepend proxychains to any command and the traffic of that command will be routed through proxychains

for example we could do curl: 

`proxychains curl http://server_ip:port`

you would get an output like: 

![](Images/Pasted%20image%2020240111210448.png)

### Nmap 

with nmap you only need to use the `--proxies` flag, and it is typically recommended to skip the host discovery with `-Pn`: 

`nmap --proxies http://127.0.0.1:8080 SERVER_IP -p PORT -Pn -sC`

the nmap proxies may still be in development so in that case we could again prepend `proxychains` to the command 

### Metasploit

we can proxy web traffic made by metasploit modules to better investigate and debug them 

start metasploit with `msfconsole`, then to set a proxy for any exploit we can use the `set PROXIES` flag: 

![](Images/Pasted%20image%2020240111211848.png)

you can then see all the requests in the proxy: 

![](Images/Pasted%20image%2020240111212311.png)

## Burp Intruder 

two of the most important features that burp and ZAP have are the web fuzzers and web scanners 

burp's fuzzer is called Burp Intruder  
can be used to fuzz pages, directories, sub-domains, parameters, parameter values, etc. 

much more advanced than most cli based fuzzers but the free burp version is throttled at a speed of 1 request per second, which is extremely slow compared to cli which can do up to 10k requests at a time 

to start working with the intruder we can visit our site with the proxy on and right click the request and select `Send to intruder`: 

![](Images/Pasted%20image%2020240112121654.png)

### Positions

the `Positions` tab shows us where we will place the payload position pointer, or where the words from our wordlist will be placed and iterated over 

to start fuzzing for web directories our fuzzing should be in `GET /DIRECTORY/` such that existing pages would return 200 OK

we can select DIRECTORY as the payload position by wrapping it in the special character: 

![](Images/Pasted%20image%2020240112122151.png)

DIRECTORY in this case is the pointer's name, and can be anything  
can also be used to refer to each pointer in the case where we are using more than one position with different wordlists for each

next we can choose our attack type which defines how many payload pointers are used and determines which payload is assigned to which position 

we can use `Sniper` which only uses one position

**note**: make sure to leave the extra two lines at the end of the request or therer might be an error

### Payloads

for our payloads/wordlists there are 4 main things to consider: 
- payload sets
- payload options
- payload processing 
- payload encoding 

first we can configure the payload set which identifies the number of payloads we will use   
we chose an attack with only one payload position so we only need 1 payload set: 

![](Images/Pasted%20image%2020240112130427.png)

next we want to select the payload type, which is the type of payloads/wordlists we will use  

there are many different types of payloads: 
- simple list = basic and most fundamental; provide a wordlist and intruder iterates over each line in it 
- runtime file = similar to simple list but loads line-by-line as the scan runs to avoid excessive memory usage 
- character substitution = specify a list of characters and their replacements, will try all potential permutations 

![](Images/Pasted%20image%2020240112131040.png)

payload options are different for each payload type  

![](Images/Pasted%20image%2020240112131602.png)

we could add each word of our list manually with the add button or we could load one of our lists

![](Images/Pasted%20image%2020240112131551.png)

adding another wordlist or adding more of our own words on top of the loaded wordlist will be appended to the currently loaded one 

burp pro also contains a selection of existing wordlists 

remember that if you are using a very large wordlist it is better to use runtime file as the payload type rather than simple list 

payload processing allows us to determine fuzzing rules over the loaded wordlist   
for example, if we wanted to add an extension after our payload item or filter the wordlist based on specific criteria 

![](Images/Pasted%20image%2020240112133002.png)

if we wanted to add a rule that skips any lines that start with `.` we can use the add button and select `Skip if matches regex`: 

![](Images/Pasted%20image%2020240112133147.png)

the final option we have is payload encoding which lets us enable or disable payload URL-encoding: 

![](Images/Pasted%20image%2020240112133236.png)

### Options

in the options tab we can change many things like setting the number of retired on failure and pause before retry to 0

![](Images/Pasted%20image%2020240112134301.png)

`Grep - Match` enables us to flag specific requests depending on their responses 

if we are looking for responses that return 200 OK we can first enable grep match and clear the default list: 

![](Images/Pasted%20image%2020240112134457.png)

then we can add 200 OK to the list and uncheck `Exclude HTTP headers` since we are looking for HTTP headers: 

![](Images/Pasted%20image%2020240112134550.png)

we could also use `Grep - Extract` which is useful if the HTTP responses are lengthy and we only want certain parts 

### Attack 

using the start attack button we can begin to see all of the requests being made: 

![](Images/Pasted%20image%2020240112135244.png)

## ZAP Fuzzer 

zap's fuzzer is very powerful for fuzzing web end-points but is missing some features that burp has   
however, it doesn't throttle the fuzzing speed 

to replicate what we did with burp lets first send a request to `http://SERVER_IP:PORT/test` so we can fuzz on test: 

![](Images/Pasted%20image%2020240112153038.png)

then right click the `Fuzz` button to open the fuzzer window: 

![](Images/Pasted%20image%2020240112153122.png)

the main options we want to configure are: 
- fuzz location 
- payloads 
- processors 
- options 

### Locations 

the fuzz location is similar to the intruder payload position, it is where our payloads will be placed

first highlight the term we want to fuzz and use the add button to open up the options: 

![](Images/Pasted%20image%2020240112153344.png)

### Payloads

fuzz has payload types but aren't as advanced as burp's 

some of them are: 
- file = select a payload wordlist from a file
- file fuzzers = select wordlists from built-in databases of wordlists
- numberzz = sequences of numbers with custom increments 

zap has built in wordlists that are available for free: 

![](Images/Pasted%20image%2020240112161630.png)

even more can be installed from the zap marketplace 

### Processors 

we can use some payload processors to modify each word of our wordlist such as: 
- base64 decode/encode
- MD5 hash
- postfix string 
- prefix string
- SHA-1/256/512 hash
- url decode/encode
- script

for our example we will do url encoding to make sure that our request does not generate errors: 

![](Images/Pasted%20image%2020240112162059.png)

### Options 

some of the options we have available to us are to set the concurrent threads per scan: 

![](Images/Pasted%20image%2020240112162340.png)

we could also traverse through the payloads depth first which attempts all words on a single payload position before moving to the next  
breadth first would run every word on all payload positions before moving to the next word 

### Start 

once we start the fuzzer we can see each request and sort them: 

![](Images/Pasted%20image%2020240112162647.png)

there are other fields that might indicate a successful hit like `Size Resp. Body` which could indicate that we got a different page or `RTT` for attacks like time-based SQL injections 

the skills page that we found sets the cookie to the MD5 hash of the username: 

![](Images/Pasted%20image%2020240112163015.png)

lets visit the page and get a request to fuzz: 

![](Images/Pasted%20image%2020240112163134.png)

now lets add a payload on our cookie value:

![](Images/Pasted%20image%2020240112163914.png)

then lets add a processor onto it that converts each word in our wordlist to its MD5 hash: 

![](Images/Pasted%20image%2020240112163850.png)

then once we start the fuzzer we can see a response with a different size: 

![](Images/Pasted%20image%2020240112164512.png)

## Burp Scanner 

burp comes with burp scanner which is a powerful scanner for web vulnerabilities   
a crawler is used for building the website structure, and a scanner for passive and active scanning 

burp scanner is a paid-only feature 

### Target scope 

to start a scan we can: 
- start scan on specific request from proxy history 
- new scan on a set of targets 
- scan on items in-scope

we can start a scan by right-clicking on a request in HTTP history: 

![](Images/Pasted%20image%2020240112171135.png)

you could also select `New scan` in the dashboard to start a new scan on a set of custom targets 

`Target Scope` can be used to define a custom set of targets that will be processed 

going to `Target -> Site map` will show a list of all directories and files burp has detected: 

![](Images/Pasted%20image%2020240112171923.png)

you can right click any of these to add them to our scope 

we may also need to exclude items from our scope if scanning them could be dangerous or end our session like a logout function  

### Crawler 

going to the dashboard and starting our scan you can see it gives us two options, crawl and audit or crawl: 

![](Images/Pasted%20image%2020240112172214.png)

a web crawler navigates a site by accessing any links found in its pages, using forms, and examining any requests it makes to build a map of the site  

crawl and audit will run the scanner after its crawler 
remember that crawling will not fuzz for new directories

we can start a crawl and go to `Scan configuration` to configure our scan   
here we can change things like the crawling speed or limit, choose to attempt to log in to any forms, etc.   

you can also use `Select from library` which gives preset configs to choose from: 

![](Images/Pasted%20image%2020240112174526.png)

next we can do the fastest crawl strategy and continue to the `Application login` tab  
here we can add a set of credentials that burp will use to attempt to login with   
can also add a set of steps to follow when logging in   

once the scan is complete you can view the final site map in `Target -> Site map`

### Passive scanner

now that the site map is build we can select to scan the target for vulnerabilities 

if we do `Crawl and Audit` burp will do two types of scans, passive and active  

passive scans do not send requests but will analyze the source code of pages to try to identify vulnerabilities  
without sending requests, the scanner can only suggest a list of potential vulnerabilities   

to initiate a passive scan we can select the target in `Target -> Site map`, then right-click to select a passive scan   
`view details` will reveal the identified vulnerabilities, you can also view this in the `Issue activity` section of the dashboard 

### Active scanner

an active scan will: 
- run a crawl and a web fuzzer to identify all possible pages
- run a passive scan on all identified pages
- sends requests to all identified vulnerabilities in the passive scan 
- performs javascript analysis to identify further vulnerabilities 
- fuzzes insertion points and parameters to look for common vulnerabilities like XSS, command injection, SQL injection, and other common web vulnerabilities 

setting the audit `configurations` will enable us to select what types of vulnerabilities we want to scan, where the scanner will insert the payloads, 

like with passive scans, we are usually looking for vulnerabilities with high severity and firm/certain confidence

### Reporting

going to `Target -> Site map`, right-clicking on our target, and selecting `Issue -> report issues for this host` will prompt us to select the export type for the report and what info we want to include in it 

![](Images/Pasted%20image%2020240112182213.png)

## ZAP Scanner 

zap's scanner also has the ability to crawl and conduct active/passive scans 

ZAP Spider is the crawler and can be found by right-clicking a request and doing `Attack -> Spider` 

![](Images/Pasted%20image%2020240113162458.png)

zap also has a scope which is the set of URLs that zap will test if we start a generic scan 

after our scan is finished we can see the site map in the lefthand `Sites` menu under our target site: 

![](Images/Pasted%20image%2020240113162910.png)

we could also do an Ajax spider crawl which also tries to identify links requested through javascript ajax requests which could be running on the page after it loads 

as spider runs it is running its passive scanner on each response to look for potential vulnerabilities  
you can see any found vulnerabilities in the alerts menu: 

![](Images/Pasted%20image%2020240113164027.png)

once we have our site map we can right-click on it to initiate an active scan on all identified pages: 

![](Images/Pasted%20image%2020240113164420.png)

if we have not already done the spider scan, doing an active scan will perform it first 

we can also generate a report with all of the findings by going to `Report -> Generate HTML report`: 

![](Images/Pasted%20image%2020240113165201.png)

![](Images/Pasted%20image%2020240113165427.png)

when our scan of the target finishes we can see a high priority command injection vulnerability be found: 

![](Images/Pasted%20image%2020240113171205.png)

using the resender tool we can edit the example request to instead look for the file /flag.txt: 

![](Images/Pasted%20image%2020240113171305.png)

## Extensions

both burp and zap have community extensions  
burp has the Extender and BApp store   
ZAP has the ZAP Marketplace  

### BApp store 

you can see this in the `Extender -> BApp store` tabs: 

![](Images/Pasted%20image%2020240113172754.png)

a good one to install is `Decoder Improved`: 

![](Images/Pasted%20image%2020240113172909.png)

you can see each installed extension in the top menu tabs: 

![](Images/Pasted%20image%2020240113172941.png)

some of the better extensions consider are: 

![](Images/Pasted%20image%2020240113173407.png)

### ZAP marketplace

use the `Manage Add-ons` to see the marketplace tab: 

![](Images/Pasted%20image%2020240113173455.png)

![](Images/Pasted%20image%2020240113173502.png)

we can use the FuzzDB Files and FuzzDB Offensive addons in our previous exercise to use the `command-execution-unix.txt` wordlist: 

![](Images/Pasted%20image%2020240113174108.png)

this way we can try many different commands to quickly find ones that produce unique results: 

![](Images/Pasted%20image%2020240113174232.png)

### Closing thoughts

burp and zap are essential tools along with Nmap, Hashcat, Wireshark, tcpdump, sqlmap, Ffuf, Gobuster, etc.   

with these tools under our belt we can now try web attack focused boxes on the main HTB platform 

## Skills Assessment - Using Web Proxies

in this assessment we are performing penetration testing for a local company 

for each of the scenarios, determine the feature of burp/zap that would best fit and use them to find the flags

### The /lucky.php page has a button that appears to be disabled. Try to enable the button and click on it to get the flag

first lets capture a request to the page to see how we might manipulate it: 

![](Images/Pasted%20image%2020240113174947.png)

we can see that the button has a `disabled` attribute, so now lets capture the response to edit it out: 

![](Images/Pasted%20image%2020240113175143.png)

we can then visit the site and click the button, but from the response we don't usually see any flags because there is only a change for the flag to be seen

so lets use the captured click request to resend it over and over: 

![](Images/Pasted%20image%2020240113180620.png)

if we keep resending it we can see a response with a different size that contains the flag at the end: 

![](Images/Pasted%20image%2020240113180817.png)

### The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters

lets send the request to get the cookie: 

![](Images/Pasted%20image%2020240113182258.png)

after using ASCII and then base64 decoding I get the value: 

![](Images/Pasted%20image%2020240113182827.png)

### Once you decode the cookie, it appears to be an MD5 hash missing its last character. Try to fuzz the last character of the decoded MD5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. 

we will first need a request with the cookie set: 

![](Images/Pasted%20image%2020240113190227.png)

then we can send it to the burp intruder and specify the cookie as our payload position: 

![](Images/Pasted%20image%2020240113190302.png)

the exercise specifies to use alphanum-case.txt as our wordlist to find the missing letter, so we specify this in our payload options

![](Images/Pasted%20image%2020240113190409.png)

then in order to do the reverse encodings (base64 then ASCII), we first add a prefix of the 31 character MD5 hash to each of our words in our wordlist: 

![](Images/Pasted%20image%2020240113190401.png)

if we sort our results by length we can find many results with shorter response lengths that contain the flag: 

![](Images/Pasted%20image%2020240113190642.png)

### You are using the `auxiliary/scanner/http/coldfusion_local_traversal` tool in Metasploit but it is not working. Capture the request and find the directory being called in "/XXXXX/administrator/..."

in metasploit I use the tool on the target and specify the proxy port: 

![](Images/Pasted%20image%2020240113191529.png)

then in burp the captured request reveals the directory: 

![](Images/Pasted%20image%2020240113191551.png)

