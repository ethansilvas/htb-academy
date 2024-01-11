
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

![](../Images/Pasted%20image%2020240110140558.png)

then we will be prompted about configurations, there are either burp default configurations or you can load a config file 

ZAP also has the ability to be ran as an app or as a jar  
can also launch from terminal with `zaproxy`   

zap gives the option to save a project without paying, but for our purposes we will only need temp projects 

## Proxy Setup 

with burp and zap we can set them up as a proxy for any app so that all requests can be routed through them  

### Pre-configured browser 

first we need to configure our browser to use the tools as the proxy, or use the pre-configured browser  

in burp there is the option to open the pre-configured browser in the `Proxy -> Intercept` menu: 

![](../Images/Pasted%20image%2020240110173618.png)

in ZAP there is a firefox button in the top toolbar: 

![](../Images/Pasted%20image%2020240110174057.png)

### Proxy setup 

burp and zap use 8080 for the web proxy listening port by default  

if we wanted to serve the web proxy on a different port we can do so in burp under `Proxy -> Options` and in zap under `Tools -> Network -> Local Servers/Proxies` 

with the foxyproxy browser extension you can modify the different proxy IPs or ports you want to use: 

![](../Images/Pasted%20image%2020240110174821.png)

### Installing CA certificate

with our browser we will need to install the web proxy's CA certificates so that all HTTPS traffic is properly routed  

you can get the burp certificate with the foxyproxy set and going to `http://burp`: 

![](../Images/Pasted%20image%2020240110183038.png)

you can get them in zap by going to `Tools -> Network -> Server Certificates` 

![](../Images/Pasted%20image%2020240110183320.png)

then with the certificates you can go to `about:preferences#privacy` in firefox and view your certificates

in the `Authorities` tab you can import the files downloaded from burp and zap: 

![](../Images/Pasted%20image%2020240110183527.png)

now all firefox web traffic will start routing through our proxy 

## Intercepting Web Requests 

with our proxy in place we can intercept and manipulate HTTP requests sent by the web app  

### Intercepting requests 

with burp we go to the `Proxy` tab and make sure request interception is on  

after going to our spawned target we can see the request show up in burp: 

![](../Images/Pasted%20image%2020240110191213.png)

since this acts as a MITM we can choose to forward or drop the request, forwarding it allows us to then load the site: 

![](../Images/Pasted%20image%2020240110191250.png)

for zap, interception is off by default and we can enable it with the green button in the top bar: 

![](../Images/Pasted%20image%2020240110191937.png)

then after visiting the site you can see the requests just like burp: 

![](../Images/Pasted%20image%2020240110192029.png)

zap also inlcudes a HUD that is visible once we forward requests and view the site: 

![](../Images/Pasted%20image%2020240110192210.png)

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

![](../Images/Pasted%20image%2020240110193741.png)

![](../Images/Pasted%20image%2020240110193729.png)

we can now manipulate the request to insert characters that would otherwise be blocked by the front-end protection code   
there still may be protections in the backend but we can check by manipulating the request before forwarding it 

if we replace the IP we provided with `;ls;` we can get the ls command response: 

![](../Images/Pasted%20image%2020240110194038.png)

## Intercepting Responses
