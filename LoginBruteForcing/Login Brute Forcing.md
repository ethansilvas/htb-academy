
## Introduction to Brute Forcing

brute force = attempting to guess passwords or keys by automated probing 

files that contain hashed passwords: 
- Windows
	- unattend.xml
	- sysprep.inf
	- SAM
- Linux 
	- shadow
	- shadow.bak
	- password

hashes can't be backwards calculated so brute forcing calculates common password hashes to see if there are any matches in these files   
this is offline brute-forcing

online brute forcing is attacking an online system by interacting with it through something like a login form 

tools for login brute forcing: 
- Ncrack
- wfuzz 
- medusa 
- patator 
- hydra

## Password Attacks 

in this example we have found an unusual host on the network that is a web server using a non-standard port 

many web servers or individual contents on the web servers are still using the basic HTTP AUTH scheme 

two parallel HTTP specification authentication mechanisms:
1. Basic HTTP AUTH = authenticate user to the HTTP server
2. Proxy server authentication = authenticate user to intermediate proxy server 

both use requests, response status codes, and response headers  
differences in the status codes and header names used 

basic http auth uses **user id** and **password** for auth: 
1. client sends request without auth info with its first request 
2. server responds with WWW.Authenticate header field which requests client to provide creds 
3. client asked to submit the auth info 
4. in its response, the server transmits realm = character string that tells the client who is requesting data
5. client uses Base64 method for encoding the identifier and password 
6. encoded character string is transmitted to the server in the authorization header field 

several types of password attacks: 
- dictionary attack
- brute force
- traffic interception
- man in the middle 
- key logging 
- social engineering 

### Brute force attack

does not depend on wordlist of common passwords, instead tries every possible combo of characters for the length specified 

ex: password length of 4 would try aaaa -> zzzz  
26x26x26x26  

hydra performs brute forces over a network 

dictionary attacks increase our chances of guessing the correct password 

### Dictionary attack 

tries to guess passwords with the help of lists 

pwnbox has passwords in `/opt/useful/SecLists/Passwords` and usernames in `/opt/useful/SecLists/Usernames`

there are many methodologies to dictionary attacks: 
- online brute force attack = attacking live app over the network like HTTP, HTTPS, SSH, FTP, etc. 
- offline brute force attack = crack a hash of an encrypted password 
- reverse brute force attack = use a single common password with a list of usernames on a certain service 
- hybrid brute force attack = creating a customized password wordlist built using known intelligence on the user or service 

## Default Passwords 

many accounts have default passwords due to laziness, forgetfulness, and poor management 

### Hydra 

tool for login brute forcing 

`apt install hydra -y`

very common to find pairs of usernames and passwords used together since default service passwords are often left unchanged   
better to start with wordlist of credentialed pairs first like `test:test`

```shell-session
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /
```

common for admin to overlook test or default accounts and their creds  
always advised to start by scanning for default credentials  
even worth testing top 3-5 common combos manually

using the command on the target produces valid credentials: 

![](../Images/Pasted%20image%2020231210190239.png)

![](../Images/Pasted%20image%2020231210190325.png)

## Username Brute Force