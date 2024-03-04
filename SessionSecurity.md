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

