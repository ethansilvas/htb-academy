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

