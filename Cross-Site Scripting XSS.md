
## Introduction

among the most common web vulnerabilities are XSS attacks   
these take advantage of a flaw in user input sanitation to write JS code to the page and execute it on the client-side 

### What is XSS 

typical web app works by getting HTML code from the back-end server and rendering it on the client-side browser 

a malicious user can inject JS code in an input field for something like a comment or reply so that when another user visits the page they will execute the JS code unknowingly 

XSS solely executed on the client-side; do not directly affect the back-end server   
only affect the user who is executing the vulnerability   

direct impact on back-end server may be low but are common in web apps   
medium risk = low impact + high probability 

we aim to reduce medium risk like this: 

![](Images/Pasted%20image%2020240124110512.png)

### XSS attacks 

wide range of attacks since anything can be executed through the browser JS code   

basic example is having target send their session cookie to an attacker's web server   
another is having the target execute API calls that do things like change their password   
many other types that range from btc mining or displaying ads 

XSS attacks are limited to the browser's JS engine (like V8 in chrome)  
can't execute system-wide JS code  
modern browsers also limit to the same domain of the vulnerable site   
however there are still attacks like finding a binary vulnerability in a web browser (like a heap overflow) to then use XSS to execute JS exploit in browser that breaks out of browser's sandbox to execute code on target's machine 

### Types of XSS

three main types: 
- stored (persistent) XSS = most critical; user input is stored on the backend database and displayed upon retrieval (posts or comments)
- reflected (non-persistent) XSS = user input is displayed on the page after being processed by the backend server but is not stored (search result or error message) 
- DOM-based XSS = non-persistent; user input is directly shown in the browser and is completely processed on the client-side without reaching backend (through client-side http parameters or anchor tags)

## Stored XSS 

stored or persistent XSS that stores our payload on the backend database and is retrieved when the user visits the page means that our attack will affect any user   
furthermore, the payload may need removing from the backend database

for our target site we can see that our input is displayed back to us: 

![](Images/Pasted%20image%2020240124112359.png)

### XSS testing payloads 

we can test if the page is vulnerable to XSS with a basic payload: 

`<script>alert(window.origin)</script>`

![](Images/Pasted%20image%2020240124112606.png)

we can confirm that the page is vulnerable to XSS further by looking at the page source: 

![](Images/Pasted%20image%2020240124112832.png)

many modern web apps use cross-domain IFrames to handle user input so even if the form is vulnerable to XSS then it won't affect the main app    
this is why in our example we are showing the value of `window.origin` in the alert box instead of a value like `1` because then the alert box reveals what URL it is being executed on   
confirms what form is vulnerable in case an IFrame was being used 

some browsers block `alert()` so another payload is to use `<plaintext>` which stops rendering the HTML code and displays it as plaintext    

another easy payload is `<script>print()</script>` which pops up the browser print dialog which is unlikely to be blocked by any browsers 

in our examples we can refresh the page and see our payloads again, which means that the XSS is in fact stored on the backend and will affect any users visiting the page 

to find the flag for this target we can modify our script to get the cookie: 

`<script>alert(document.cookie)</script>`

## Reflected XSS 

reflected XSS gets processed by the backend server and DOM-based is completely processed on the client-side   
both are non-persistent XSS, meaning they are not persistent through page refreshes   
attacks will only affect the target user and not all other users who visit the page

reflected XSS occurs when the input reaches the backend and gets returned to us without being filtered or sanitized   
many cases where our entire input might get returned to us, like error messages or confirmation messages 

with our target we can retry our test string: 

![](Images/Pasted%20image%2020240124135339.png)

we can see that out input `test` is included in the error message   
if this input is not filtered or sanitized then it might be vulnerable to XSS 

we can then try the window.origin payload: 

![](Images/Pasted%20image%2020240124135459.png)

the resulting text says `Task ' '` because our script element does not get rendered by the browser 

we can confirm in the source code that our payload worked: 

![](Images/Pasted%20image%2020240124135629.png)

then when we refresh the page we will not see our payload anymore, meaning that it is non-persistent 

if the XSS is not persistent, how do we target victims with it?  
this depends on the HTTP request being used to send our input to the server  

for this target we can see that the site uses a GET request to perform the add task function: 

![](Images/Pasted%20image%2020240124135909.png)

so to target a user with this vulnerability we can send them a URL containing our payload 

we can copy the url being sent: 

`http://94.237.53.58:36741/index.php?task=test`

then modify it with our payload: 

`http://94.237.53.58:36741/index.php?task=<script>alert(window.origin)</script>`

## DOM XSS 

occurs when JS is used to change the page source through the DOM 

on our target server we can try the test string: 

![](Images/Pasted%20image%2020240124141407.png)

however, when we use the add button there are no requests being made: 

![](Images/Pasted%20image%2020240124141452.png)

in the url we can see that it is using `#`: 

![](Images/Pasted%20image%2020240124141542.png)

this means that it is a client-side parameter that is completely processed on the browser 

we can also see in the pages source that our test string will not appear in it 

### Source and sink 

to understand DOM XSS we need to understand the concept of source and sink of the object displayed on the page  

source = JS object that takes user input, could be anything like URL parameter or input field     
sink = function that writes the user input to a DOM object on the page   

if sink does not sanitize input then it will be vulnerable to XSS 

some common JS functions to write to DOM objects: 
- `document.write()`
- `DOM.innerHTMl`
- `DOM.outerHTMl`

some jquery functions that write to DOM: 
- `add()`
- `after()` 
- `append()`

the above functions will not sanitize input and will output it exactly 

viewing the page source we can see that the source is being taken from the task parameter: 

![](Images/Pasted%20image%2020240124143017.png)

we can see that .innerHTML is being used to write the task variable in the todo DOM 

### DOM attacks

innerHTML will not allow script tags as input but other payloads will work like: 

`<img src="" onerror=alert(window.origin)>`

this will create an image object with an onerror attribute that executes JS code when the image isn't found   
our code will always be executed because we provide a blank image link

to target users with this vulnerability we can again use the URL: 

`http://83.136.251.235:49425/#task=%3Cimg%20src=%22%22%20onerror=alert(document.cookie)%3E`

## XSS Discovery 

### Automated discovery 

almost all web app vulnerability scanners have XSS detection   
usually do two types of scanning, passive and active 

active scans work by sending various XSS payloads into input fields and comparing the rendered page source to see if the payload can be found in it, which might indicate successful XSS 

must always manually confirm any found injections 

common open source tools for XSS discovery: 
- XSS strike 
- Brute XSS
- XSSer

can try XSS strike by cloning it: 

```shell
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
```

then run the script and provide url with `-u`: 

```shell
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```

### Manual discovery 

difficulty of finding XSS depends on level of security of the app   
advanced XSS usually involves code review skills 

#### XSS payloads

most basic method of looking for vulnerabilities is manually testing various XSS payloads 

can find lists of XSS payloads online like: 
- payloadallthethings
- payloadbox 

XSS can be injected into any input in the HTML page like input fields or HTTP headers like Cookie or User-Agent

many payloads will not work for all test cases because they are all designed to work with certain types of injections 

### Code review 

most reliable method of detecting XSS is code review   
can write custom payloads based on how our input is being handled   

unlikely to find any XSS through payload lists or XSS tools for advanced web apps 

look into 
- secure coding 101
- whitebox pentesting 101: command injection 

to try some of these techniques we can see our target has a registration form: 

![](Images/Pasted%20image%2020240124152327.png)

when filling out a dummy form we can capture the URL: 

![](Images/Pasted%20image%2020240124152354.png)

`http://94.237.54.75:32571/?fullname=test&username=e&password=asdf&email=g%40gmail.com`

using this url we can run it through tools like XSStrike: 

![](Images/Pasted%20image%2020240124153204.png)

and we can see from the results that the email field looks to be vulnerable: 

![](Images/Pasted%20image%2020240124153229.png)

when normally using the UI any payloads will not be accepted, but by modifying the URL we can see our input being reflected: 

![](Images/Pasted%20image%2020240124153323.png)

