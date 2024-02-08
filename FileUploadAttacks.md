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
