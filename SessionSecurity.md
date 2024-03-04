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

