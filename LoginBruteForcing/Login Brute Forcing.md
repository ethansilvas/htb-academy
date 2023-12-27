
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

now we will try to attack HTTP basic auth by using separate wordlists for usernames and passwords 

one of the most common wordlists is `rockyou.txt`  
has over 14 million unique passwords collected from leaded dbs  

hydra requires at least 3 specific flags if the credentials are in a single list: 
- credentials 
- target host 
- target path 

`-L` = usernames wordlist   
`-P` = passwords wordlist   
`-f` = stop on the first successful login   
`-u` = tries all users on each password, instead of all passwords on one user before going to the next  

`hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -P ./rockyou.txt -u -f 178.35.49.134 -s 32901 http-get /`

this command will end up taking a long time because although default passwords are commonly used together, they are not among the top for individual wordlists  
so this likely means that the default password was buried deep in rockyou.txt 

### Username brute force 

if we only wanted to brute force either the username or password, we can set a static value for them  
use the same flag but lowercase 

`-l` = static username 
`-p` = static password 

`hydra -L /opt/useful/SecLists/Usernames/Names/names.txt -p amormio -u -f 178.35.49.134 -s 32901 http-get /`

using this method on the previously found target of admin:admin results in the admin username being found with the static password: 

![](../Images/Pasted%20image%2020231227144218.png)

## Hydra Modules 

in the previous exercises we found an admin login form  
this will be interesting to try to gain access to without generating a lot of network traffic  
with the admin panels we can manage servers, services, and configs  
many admin panels also have features like b374k shell that could allow us to execute OS commands directly 

when we get to the admin panel, to generate as little traffic as possible, it is a good idea to try the top 10 most popular admin credentials like admin:admin  
if this doesn't work then we can try password spraying  
this will try leaked passwords across multiple accounts 

### Brute forcing forms 

hydra lists two http modules that will be useful for this admin panel cracking: 
- http[s]-{head|get|post} = basic http auth like we used before 
- http[s]-{get|post}-form = login forms like .php or .aspx and others 

first we need to find out if the form is GET or POST by attempting one login and looking at the url: 

the url did not paste any of the input into the url when attempting to login, so this means that it is a POST form: 

![](../Images/Pasted%20image%2020231227150848.png)

now we can form our hydra http-post-form command: 
`/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]` 

for hydra to understand if the login was successful or not we have to provide a unique string from the source code of the page we're logging in on  
hydra will examine the source code response page after each attempt and look for the string we provided 

Fail = FALSE = F=html_content  
Success = TRUE = S=html_content  

we can provide either string and it will keep trying until the fail string is not found or the success string is found  

there is unfortunately no found string that we can use for the failed state: 

![](../Images/Pasted%20image%2020231227152643.png)

and we can't use "Admin Panel" because if that string exists in the success page then hydra won't be able to tell the difference 

what we can do though is use something like the login button  
it is very unlikely that the login button will also exist in the successful login page 

```html
<form name="login" autocomplete="off" class="form" action="" method="post">
```

we don't even need to use the full thing, we can just use `<form name="login"`:

`"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"`

