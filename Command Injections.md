
## Intro to Command Injections 

command injections are among the most critical types of vulnerabilities  
allows us to execute commands directly on the back-end hosting server    
if the web app uses user-controlled input to execute system commands on the back-end server then we might be able to inject a malicious payload 

### What are injections 

injection vulnerabilities are #3 risk for OWASP top 10 web app risks 

most common types of injections: 
- OS command injection = user input as part of OS command
- Code injection = user input within function that evaluates code 
- SQL injection = user input is used as part of SQL query 
- XSS/HTML injection = exact user input is displayed on the web page 

many other types like LDAP, NoSQL, HTTP header, XPath, IMAP, ORM 

### OS command injections 

user input we control must directly or indirectly go into a web query that executes system commands   
all web programming languages have functions to execute OS commands directly on the back-end server 

#### PHP example 

PHP has commands like `exec`, `system`, `shell_exec`, `passthru` or `popen`

this is an example of code vulnerable to command injections: 

![](Images/Pasted%20image%2020240131113737.png)

in the above code, user input is directly used with the `touch` command which could be used to execute arbitrary system commands on the back-end server 

#### NodeJS example 

nodejs has functions like `child_process.exec` or `child_process.spawn` similar to php 

here is a nodejs example similar to the above PHP code: 

![](Images/Pasted%20image%2020240131114156.png)

again, user input is being directly used with the touch command 

command injection vulnerabilities are not unique to web apps and can also affect other binaries and thick clients 