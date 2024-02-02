
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

## Bypassing Other Blacklisted Characters 

besides injection operators and space characters, commonly blacklisted characters are `/` and `\` because they are necessary to specify directories in windows and linux 

### Linux 

many different ways to use slashes in our payload   

one technique we can use to replace slashes or any character is through linux environment variables like we did with `${IFS}`   
`${IFS}` is replaced with a space, but there's no variable for slashes or semi-colons  
however, these characters can be used in an environment variable and we can specify start and length of our string to match this character 

for example we can look at the `$PATH` environment variable: 

![](Images/Pasted%20image%2020240202131709.png)

with `$PATH` we can start at the 0 character and only take a string of length 1 to grab only the `/` character: 

![](Images/Pasted%20image%2020240202131907.png)

we can do the same with `$HOME` or `$PWD` and other commands to get characters like the semi-colon: 

![](Images/Pasted%20image%2020240202132019.png)

`printenv` will print all environment variables in linux so we can look at which ones have useful characters 

now we can try to use environment variables to add a semi-colon and space to our payload: 

![](Images/Pasted%20image%2020240202132612.png)

### Windows 

the same techniques will work in windows command line  
we can `echo` a windows variable and specify a start position and a negative end position which would need to be the length of the username:

![](Images/Pasted%20image%2020240202133024.png)

we can do the same thing using the same variable in powershell   
words are considered arrays in powershell, so we need to specify the index of the character we need: 

`$env:HOMEPATH[0]`

we can also `Get-ChildItem Env:` to print all environment variables   

### Character shifting 

linux commands can shift the character we pass by 1, so we just need to find the character in the ASCII table that is just before the character we need   
we can get the ascii value with `man ascii` then add it instead of `[` in: 

`echo $(tr '!-}' '"-~'<<<[)`

`\` is on 92, before it is `[` on 91

![](Images/Pasted%20image%2020240202134254.png)

![](Images/Pasted%20image%2020240202134421.png)

powershell can do the same thing but the command will be a bit longer than linux ones 

if we wanted to see the name of the user in the `/home` directory we can use the following payload: 

`127.0.0.1%0a{ls,${PATH:0:1}home}`

![](Images/Pasted%20image%2020240202134922.png)

## Bypassing Blacklisted Commands 

specific commands like `ls` or `whoami` will also be blacklisted   
a command blacklist usually has a set or words but we can obfuscate our commands to make them look different 

### Commands blacklist 

a basic command blacklist filter could look like: 

![](Images/Pasted%20image%2020240202140616.png)

filters like this will match an exact word so if we send slightly different commands we could bypass it 

### Linux and windows 

one very command and easy obfuscation technique is inserting characters that are usually ignored by command shells like bash or powershell   
some of these characters are `'` and `"` and some others 

quotes are easiest to use and work on both windows and linux   
if we wanted to obfuscate `whoami` we can use single quotes between characters: 

`w'h'o'am'i`

the same will work with double quotes 

important to remember that we can't mix types of quotes and the number of quotes must be even 

we can see that using quotes will execute our payload: 

![](Images/Pasted%20image%2020240202141624.png)

### Linux only 

there are some other linux-only characters that bash will ignore: 
- `\`
- `$@` 

these will work the same as quotes but the number of characters do not need to be even, and we can insert only one if we want to: 

`who$@ami`

### Windows only 

characters like `^` will work the same for windows only: 

`who^ami`

adding to the previous command to find the user in the `/home` directory will allow us to view the flag file in their directory: 

![](Images/Pasted%20image%2020240202142541.png)

