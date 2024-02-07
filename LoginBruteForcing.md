# Login Brute Forcing

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

![](Images/Pasted%20image%2020231210190239.png)

![](Images/Pasted%20image%2020231210190325.png)

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

![](Images/Pasted%20image%2020231227144218.png)

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

![](Images/Pasted%20image%2020231227150848.png)

now we can form our hydra http-post-form command: 
`/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]` 

for hydra to understand if the login was successful or not we have to provide a unique string from the source code of the page we're logging in on  
hydra will examine the source code response page after each attempt and look for the string we provided 

Fail = FALSE = F=html_content  
Success = TRUE = S=html_content  

we can provide either string and it will keep trying until the fail string is not found or the success string is found  

there is unfortunately no found string that we can use for the failed state: 

![](Images/Pasted%20image%2020231227152643.png)

and we can't use "Admin Panel" because if that string exists in the success page then hydra won't be able to tell the difference 

what we can do though is use something like the login button  
it is very unlikely that the login button will also exist in the successful login page 

```html
<form name="login" autocomplete="off" class="form" action="" method="post">
```

we don't even need to use the full thing, we can just use `<form name="login"`:

`"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"`

## Determine Login Parameters 

we can find the POST parameters by intercepting the login request with Burp Suite or take a look at the source code of the site 

### Using browser

a simple way to get the POST request is to use the browser's built in network tools to view the request after attempting to login: 

![](Images/Pasted%20image%2020231227194250.png)

this will reveal the post parameters: 

`username=admin&password=admin`

can also copy as cURL to get the full request: 

`curl 'http://94.237.62.195:41370/login.php' -X POST -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://94.237.62.195:41370' -H 'DNT: 1' -H 'Authorization: Basic YWRtaW46YWRtaW4=' -H 'Connection: keep-alive' -H 'Referer: http://94.237.62.195:41370/login.php' -H 'Cookie: PHPSESSID=mldgm82ib2m2t2rk6iop77hhme' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=admin&password=admin'`

### Using burp suite 

if the site uses a lot of HTTP requests, it might be easier to use Burp to go through all of them 

first we open Burp Suite and go to the proxy tab: 

![](Images/Pasted%20image%2020231227200838.png)

enable the Burp proxy with FoxyProxy: 

![](Images/Pasted%20image%2020231227200916.png)

then after trying another login we can see the captured login on Burp: 

![](Images/Pasted%20image%2020231227201010.png)

now with the information we need, we can add it to the hydra command: 

`"/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

## Login Form Attacks

first lets use the full hydra command with a list of default usernames and passwords: 

`hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 94.237.62.195 -s 41370 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

![](Images/Pasted%20image%2020231227204223.png)

this did not find any working credentials but at least we ruled out a lot of default credentials 

since this specific login form is for admins, this could potentially rule out a lot of usernames  
we can then try many default user names such as admin

now we can try with the rockyou.txt list: 

`hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 94.237.62.195 -s 41370 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

![](Images/Pasted%20image%2020231227205301.png)

with the found password we can login: 

![](Images/Pasted%20image%2020231227205800.png)

## Personalized Wordlists 

### CUPP 

tool to generate wordlists based on information on the target  

using `cupp -i` you can generate a list: 

![](Images/Pasted%20image%2020231228165054.png)

you can filter the generated list to 
- remove shorter than 8 characters
- remove no special chars 
- remove no numbers

```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

![](Images/Pasted%20image%2020231228165655.png)

the file is now much shorter: 

![](Images/Pasted%20image%2020231228165736.png)

### Mangling 

we can still make many different permutations of our targeted wordlist 

**rsmangler** and **The Mentalist** are two tools that can stretch small wordlists to millions of lines long 

### Custom username wordlist

can use tools like **Username Anarchy** 

using username anarchy we can create a list of specialized usernames: 

![](Images/Pasted%20image%2020231228170214.png)

## Service Authentication Brute Forcing 

### SSH attack 

the command to do a service attack with hydra is simple as we specify the username/password wordlists and add `service://SERVER_IP:PORT` to the end 

hydra will suggest to add `-t 4` to the end for the max number of parallel attempts because SSH typically limits the number of parallel connections and drop other connections 

the final command looks like: 

`hydra -L bill.txt -P william.txt -u -f ssh://178.35.49.134:22 -t 4`

this can result in a username and password that we can ssh into with like so: 

`ssh b.gates@178.35.49.134 -p 22`

### FTP brute forcing 

once we are ssh'd in, we can see what other users are on the system:

`ls /home` 

we can also do local recon to see what other ports are open locally: 

`netstat -antp | grep -i list` 

if port 21 is open we can try brute forcing the FTP login with the other users we find locally 

for this example, let's assume that the admin account has hydra installed, so we can just run it on the logged in user: 

`hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1`

if we get a result we can try to FTP as that user or switch to another user: 

`ftp 127.0.0.1`

switch to the user: 

`su - m.gates`

### Brute force b.gates 

what is the flag found in the home dir of the user b.gates? 

first make sure we have our personalized password list: 

![](Images/Pasted%20image%2020231228174726.png)

make the hydra ssh command using a static username of b.gates and our personalized password list: 

![](Images/Pasted%20image%2020231228174806.png)

we have found the password **4dn1l3m!$** that we can use to ssh with 

use ssh to connect on the specified port and verify that I am logged in as b.gates: 

![](Images/Pasted%20image%2020231228174934.png)

look around in the directories and find the flag in b.gates home directory: 

![](Images/Pasted%20image%2020231228175016.png)

since the user has hydra and the shorter version of rockyou.txt, try to brute force the FTP login for the other user, m.gates

using the loopback IP I can brute force the password for the m.gates user: 

![](Images/Pasted%20image%2020231228180159.png)

then I switch to that user: 

![](Images/Pasted%20image%2020231228180251.png)

then in the home directory I can see the flag: 

![](Images/Pasted%20image%2020231228180338.png)

## Skills Assessment - Website

there is one single TCP port open and there is likely weak credentials that can be brute forced 

### Brute force the authentication 

we have our target IP and port but it is username and password authenticated: 

![](Images/Pasted%20image%2020231228200101.png)

to start, I wanted to try a very quick scan and only did the top 17 usernames and top 15 passwords:

![](Images/Pasted%20image%2020231228201228.png)

luckily this worked with the `top-usernames-shortlist.txt` and `best15.txt` files and it resulted in the credentials of user and password 

using this to login you can get past the first authentication check: 

![](Images/Pasted%20image%2020231228201503.png)

### Admin panel 

the next login reveals a similar admin panel that we have done in the previous exercises: 

![](Images/Pasted%20image%2020231228201616.png)

first lets see if this is a POST or GET form: 

![](Images/Pasted%20image%2020231228202209.png)

this is a post form so now we want to form our hydra command  

we want our command to look something like this: 

`"/login.php:user=^USER^&pass=^PASS^:incorrect"`

so now lets open the POST call in Burp Suite: 

![](Images/Pasted%20image%2020231228202539.png)

from this we can see our username and password structure and now we can form our command: 

`"/admin_login.php:user=^USER^&pass=^PASS^:[true or false]"`

now all we need is a unique string from the source code to determine if the login failed or passed

we can see in the source HTML the login form element: 

![](Images/Pasted%20image%2020231228202924.png)

so now we can finalize our command to: 

`"/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"`

first we will try with a short list of common admin passwords `ftp-betterdefaultpasslist.txt`:

![](Images/Pasted%20image%2020231228203343.png)

this did not reveal any passwords so lets increase our username and password list lengths

the approach I took for this next task was to run one longer brute force with rockyou.txt and a list of usernames while I tried shorter searches in the background

my long search didn't actually take that long and I found the credentials with `top-usernames-shortlist.txt` and rockyou.txt: 

![](Images/Pasted%20image%2020231228205122.png)

another search I ran that did not get results was trying a static admin username with `cirt-deafult-passwords.txt`: 

![](Images/Pasted%20image%2020231228205237.png)

I also tried smaller searches like the ftp-betterdefaultpasslist.txt list, but the rockyou.txt search just didn't take that long to find the credentials 

with the found credentials I can login and see the flag: 

![](Images/Pasted%20image%2020231228205932.png)

## Skills Assessment - Service Login

given an IP of an online academy we want to find weak credentials being used for the website itself and other services that it is using 

this will likely require usage of more specified password lists based on the employees 

from the previous exercise we know that the user in this case is Harry Potter, so using 

### Specific wordlists

first lets use CUPP to generate a specified wordlist for Harry Potter: 

![](Images/Pasted%20image%2020231228213356.png)

we know from after logging into the admin panel that the password must be
- 8 characters or more 
- have numbers 
- have special characters 

lets do the same filters that we did last time: 

![](Images/Pasted%20image%2020231228214009.png)

so now instead of 28k passwords we have 10k that fit the password requirements

now lets create a list of specialized usernames with Username Anarchy: 

![](Images/Pasted%20image%2020231228214548.png)

### Service brute force 

doing a quick nmap scan with our known source port reveals that SSH is open: 

![](Images/Pasted%20image%2020231228214912.png)

so now lets see if we can brute force into ssh with our specialized usernames and passwords: 

![](Images/Pasted%20image%2020231228221626.png)

this ended up taking too long so instead I followed the hint to shorten my search by trying CUPP with less information than the full thing I filled out previously 

for this search I instead did first and last name with special characters and numbers: 

![](Images/Pasted%20image%2020231228223336.png)

then with the same list of generated usernames I tried a brute force and it worked very quickly: 

![](Images/Pasted%20image%2020231228223431.png)

now I can successfully connect to SSH with the credentials: 

![](Images/Pasted%20image%2020231228223618.png)

viewing the current directory I can see the flag.txt file with the first flag

### Second user brute force

while logged into the harry.potter account in SSH I can see that there is another user I can access: 

![](Images/Pasted%20image%2020231228223838.png)

we can see that ftp is open again with netstat: 

![](Images/Pasted%20image%2020231228224056.png)

using the loopback IP we can try to brute force the other user with the rockyou-30.txt list which is in the harry.potter user's home directory: 

![](Images/Pasted%20image%2020231228224807.png)

then with these credentials I can switch to the user and grab the flag from their home directory: 

![](Images/Pasted%20image%2020231228225317.png)

