
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

## Detection 

the process of detecting basic OS command injections is the same process for exploiting them   
we attempt to append our command through various injection methods   
might not be true for advanced injections because we may use fuzzing methods or code reviews to identify them 

### Command injection detection 

our target site has input for pings: 

![](Images/Pasted%20image%2020240131115033.png)

from the output we can see that the `ping` command is being used, and it might be something like: 

`ping -c 1 <input>`

if our input is not sanitized then we might be able to inject another command 

### Command injection methods 

- `;` = `%3b` - executes both commands 
- `\n` = `%0a` - both 
- `&` = `%26` - both and typically second output shown first 
- `|` = `%7c` = both but only second output shown 
- `&&` = `%26%26` = both if first succeeds 
- `||` = `%7c%7c` = second only if first fails 
- backticks = `%60%60` = both for linux only 
- `$()` = `%24%28%29` = both for linux only 

these operators can generally be used regardless of web app language, framework, or back-end server  
there are some odd exceptions like `;` which won't work with windows command line (CMD) 

## Injecting Commands 

### Injecting our command 

we can first try adding a semi-colon and appending our intended command to hopefully make the final command something like: 

`ping -c 1 127.0.0.1; whoami`

when we try to use our payload we get an error message: 

![](Images/Pasted%20image%2020240131120433.png)

however, this appears to only be for the frontend as we can see no requests are sent through: 

![](Images/Pasted%20image%2020240131120513.png)

## Bypassing front-end validation 

the easiest method to customize HTTP requests is to use a web proxy 

we can send a normal query and intercept it to then send it to the repeater: 

![](Images/Pasted%20image%2020240131121044.png)

we can then edit this request and URL encode it with `CTRL+U`: 

![](Images/Pasted%20image%2020240131121151.png)

then we can see our command worked in the response: 

![](Images/Pasted%20image%2020240131121256.png)


