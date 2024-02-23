# Web Attacks

## Introduction to Web Attacks

web attacks are the most common types of attacks against companies   

attacking external-facing web apps can lead to compromise of internal network which can lead to stolen assets or disrupted services   
even if the org doesn't use external facing web apps they will still likely use internal ones or external facing API endpoints, both of which are still vulnerable to the same types of attacks 

### HTTP verb tampering 

these attacks exploit web servers that accept many HTTP verbs and methods   
can be exploited by sending malicious requests using unexpected methods which may lead to bypassing authentication or security controls against other web attacks   

these are one of many other HTTP attacks that can be used to exploit web server configs by sending malicious HTTP requests 

### Insecure direct object references (IDOR)

among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers   
so common because of a lack of solid access control system on backends   

web apps store users files and info, which may use sequential numbers or user IDs to identify them   
suppose the app exposes direct access to these files, in this case we can then access other user's files and info by simply guessing or calculating their file IDs 

### XML external entity (XXE) injection 

many web apps parse XML data; suppose they use outdated XML libraries to parse and process user XML input data, then it would be possible to send malicious files to disclose local files   
these files may contain sensitive info or source code   

can also be leveraged to steal the hosting server's credentials which could compromise the entire server and allow for RCE 

## Intro to HTTP Verb Tampering 

HTTP protocol works by accepting different HTTP methods as `verbs` at the beginning of the request   
web apps may be scripted to accept certain HTTP methods for their various functionalities and perform a particular action based on the type of request 

developers usually consider only GET and POST but any client can send any other methods in their requests   
if GET and POST are the only ones that accepted then it is more secure other than revealing sensitive error info   
there is also the case where the app accepts other methods but isn't develop to handle them like HEAD and PUT, we might be able to exploit this insecure config to gain access to functionalities that we don't have access to or bypass security controls 

### HTTP verb tampering 

HTTP has 9 different verbs that can be accepted by web servers: 
- GET 
- POST 
- HEAD - like GET but only contains the headers without the response body 
- PUT - writes the request payload to the specified location 
- DELETE - deletes the resource at specified location 
- OPTIONS - shows different options accepted by the server like accepted HTTP verbs
- PATCH - apply partial mods to the resource at the specified location 

 what makes verb tampering more common and more critical is that they are caused by misconfigs in either the backend web server or the web app 

### Insecure configurations 

insecure web server configs cause the first type of vulnerabilities   
a server's authentication config may be limited to specific methods, which would leave some HTTP methods accessible without authentication 

a sysadmin may use this config to require authentication on a page: 

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

even though it specifies GET and POST an attacker may still use other methods that wont be limited by the authentication   
this would lead to authentication bypass and allows attackers to access web pages and domains they don't have access to 

### Insecure coding 

can occur when a developer applies specific filters to mitigate vulnerabilities while not covering all HTTP methods   

lets say that the developer mitigated SQLi by using the following filter: 

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

we can see that the filter is only being tested on the GET parameter but the `$_REQUEST["code"]` parameters are being used which is open to all parameters   
if you supplied something like POST, then the GET parameters would be empty and would result in the pass by the filter 

insecure coding is more common because insecure configs are usually less prone to errors with modern server configs/documentation warnings 