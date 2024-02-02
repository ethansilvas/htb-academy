
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

we can first try adding a semi-colon and appending our arbitrary command to hopefully make the final command something like: 

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

## Other Injection Operators 

### AND operator 

`&&` will produce similar output by executing both commands: 

![](Images/Pasted%20image%2020240131122115.png)

### OR operator 

`||` will only execute the second command if the first fails to execute   
could be useful if our injection would break the original command without having a way for both commands to work 

in bash, if the first command returns exit code 0 then execution is successful   
the command would then stop and not try the other command after `||`   
if the exit code is 1 then it will execute the the next command 

we can intentionally try to break the intended command by not supplying an IP and only providing our arbitrary command: 

![](Images/Pasted%20image%2020240131122624.png)

now the response will only include our arbitrary command output: 

![](Images/Pasted%20image%2020240131122813.png)

many applications have operator types that produce the same types of results: 

![](Images/Pasted%20image%2020240131122926.png)

whitebox pentesting 101: command injection module goes further into indirect injections and blind injections 

## Identifying Filters

another type of injection mitigation is using blacklisted characters or words on the backend to detect injection attempts   
WAF can also be used to prevent injection methods 

### Filter/WAF detection 

now our target has some extra functions, so when we try our previous payloads we see a new "invalid input" message: 

![](Images/Pasted%20image%2020240201143842.png)

instead of the previous tooltip message, we can now see that we have triggered a security mechanism that denied our request 

we can see that the app used a field to output the error message, meaning that it was detected and prevented by the PHP app itself  
if the error message displayed a different page entirely with info like our IP and our request, then it may have been denied by a WAF 

if our payload looked like this: 

`127.0.0.1; whoami` 

then we can determine that there were 3 possible things that set off the error: 
- `;`
- space
- `whoami`

### Blacklisted characters 

php code that looks for specific blacklisted characters could look like: 

![](Images/Pasted%20image%2020240201144254.png)

if any character in the input string matches a character in the blacklist then the request is denied 

ideally we would like to see which character caused the request to be denied 

### Identifying blacklisted character

we can see that even just the `;` will set off the detection: 

![](Images/Pasted%20image%2020240201144504.png)

so now we can try all injection operators to see which ones might get past the filters

using the url encoded new-line we can achieve our intended command output:

![](Images/Pasted%20image%2020240201144812.png)

## Bypassing Space Filters 

### Bypass blacklisted operators

as we can see from the previous example, new line characters are typically not blacklisted  

### Bypass blacklisted spaces 

we can see that adding on to the accepted new line character will not be accepted: 

`127.0.0.1%0a+whoami`

![](Images/Pasted%20image%2020240202125044.png)

there are many ways to add spaces without using the space character 

#### Using tabs

using tabs `%09` may work because linux and windows accept commands with tabs between arguments, and they are executed the same 

we can see that using the tab character without our payload will be accepted: 

![](Images/Pasted%20image%2020240202125331.png)

#### Using $IFS

$IFS is a linux environment variable that may work because its default value is a space and a tab, which would work between command arguments 

`${IFS}` can be used where the spaces should be and the variable should be automatically replaced with a space 

we can see that this will work on our target as well: 

![](Images/Pasted%20image%2020240202125932.png)

#### Using brace expansion 

bash has a brace expansion feature which will add spaces between arguments between braces: 

`{ls,-la}`

we can use the same method in command injection to use brace expansion on our command arguments: 

`127.0.0.1%0a{ls,-la}`

![](Images/Pasted%20image%2020240202130541.png)

PayloadAllTheThings also has more space filter bypasses 

