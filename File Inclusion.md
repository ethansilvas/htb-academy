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

if we are in the index.php directory then we can move up the chain of `/var/www/html/index.php` and get into `../../../../etc/asswd`: 

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

