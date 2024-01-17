
## HyperText Transfer Protocol (HTTP)

most internet comms are made with web requests using HTTP  
HTTP is an application level protocol used to access WWW resources   
hypertext stands for text containing links to other resources and that readers can easily interpret 

HTTP comms consists of client that requests the server for a resource that the server returns after processing  
default port is 80 but can be changed to any port depending on web server config   

the same types of requests are used when we use the internet to visit different sites   
we enter fully qualified domain name as a uniform resource locator to reach the desired website 

### URL 

resources over HTTP are accessed via URL: 

![](../Images/Pasted%20image%2020240115151857.png)

a url can have components like: 
- Scheme - `http://` or `https://` - identifies the protocol being accessed by the client 
- User info - `admin:password@` - optional info that contains auth credentials separated by a colon and separated from the host with an `@`
- Host - `inlanefreight.com` - signifies the resource location; can be a hostname or IP address
- Port - `:80` - separated by host with `:`, if none is specified then it defaults to port 80 or 443 
- Path - `/dashboard.php` - points to the resource being accessed, which can be a file or a folder; if none is specified then the server returns the default index (ex: `index.html`) 
- Query string - `?login=true` - query string starts with `?` and consists of parameters like `login` and a value `true` separated by `=`; multiple parameters can be separated with `&`
- Fragments - `#status` - processed by the browsers on the client-side to locate sections within the primary resource, for example a header or section on the page

the main mandatory fields are the scheme and the host 

### HTTP flow 

![](../Images/Pasted%20image%2020240115153133.png)

the first time a client enters the url into their browser it will send a request to the DNS server to get the matching IP address   
however, browsers typically look in the respective /etc/hosts file first to see if the domain exists 

once the browser gets the IP address it will send a GET request to the default HTTP port 80 and ask for the root `/` path   
by default servers will return an index file when a request for `/` is received 

the server response will return something like index.html with a status code of OK 200 which indicates that the request was successfully processed   
then the browser will render the index.html contents 

### cURL 

cURL is a command line tool that primarily supports HTTP and other protocols   

we can send a basic HTTP request to any url like: 

`curl inlanefreight.com` 

the result in our terminal will be the raw contents of the returned HTML, JS, and CSS code: 

![](../Images/Pasted%20image%2020240115161346.png)

we can also download a page or file and output the content to a file with `-O` or `-o` to specify the file name: 

`curl -O inlanefreight.com/index.html` 

![](../Images/Pasted%20image%2020240115161527.png)

`-s` will silence any of the status text print out 

## Hypertext Transfer Protocol Secure (HTTPS)

HTTP sends requests in cleartext, HTTPS encrypts with SSL/TLS 

if someone were to intercept HTTP traffic they would only see something like `Encrypted Application Data: kj;qwlekrjoweirjf;alskjdnvzlxmcn`

data is transferred as a single encrypted stream  
however, the request may still reveal the visited URL if it contacted a clear-text DNS server  
an encrypted DNS server like 8.8.8.8 or 1.1.1.1 is best, or use a VPN to ensure all traffic is properly encrypted 

### HTTPS Flow 

![](../Images/Pasted%20image%2020240115162842.png)

if we type in `http://` instead of `https://` for a site that enforces https the browser will attempt to resolve it and then redirect the user to the webserver hosting the target site  
the server will redirect the client to HTTPS port 443 even thought the original request was using 80, and this is done using the 301 Moved Permanently response code 

then the client sends a "client hello" packet to give info about itself  
server will reply with "server hello", followed by a key exchange to exchange SSL certificates  
client verifies key/certificate and sends back a key of its own   
finally the encrypted handshake is initiated to confirm if the encryption and transfer are working 

normal HTTP traffic will continue after the connection is formed, but it will be encrypted 

it is possible to do an HTTP downgrade attack with at MITM proxy but most modern browsers, servers, and web apps protect against this 

### cURL for HTTPS 

cURL will automatically handle all HTTPS communication standards and perform the secure handshake   
but if we contact a site with an invalid SSL certificate then it will not proceed with the communication to protect against MITM attacks 

to skip the certificate check you can use `-k`: 

`curl -k https://inlanefreight.com`

## HTTP Requests and Responses

most HTTP communication is requests and responses   
requests are made by clients and processed by the server   

requests contain: 
- resource (url, path, parameters) 
- request data 
- headers or options
- etc. 

responses contain the response code and may contain the resource data if the request has access to it 

### HTTP request

![](../Images/Pasted%20image%2020240115171337.png)

this is an HTTP GET request to `http://inlanefreight.com/users/login.html`

the first line of any HTTP request contains three main fields separated by spaces: 
- Method - `GET` - HTTP method or verb which specifies action
- Path - `/users/login.html` - path to the resource being accessed; can be suffixed with a query string (ex: `?username=user`) 
- Version - `HTTP/1.1` - denote the HTTP version 

the next sets of lines contain HTTP header value pairs like Host, User-Agent, and Cookie   
these specify various attributes of a request   
need to be separated by a new line   

requests may then end with the request body and data 

HTTP version 1.X sends data in clear-text and uses new-line characters to separate fields   
HTTP version 2.X sends requests in binary and in dictionary form 

### HTTP response 

![](../Images/Pasted%20image%2020240115174000.png)

the first line of a response contains two fields separated by spaces: 
- HTTP version 
- HTTP response code 

after the first line the response lists its headers  
then it may end with the response body   

the response body is typically HTML code but could also be types like JSON, resources like images, stylesheets, scripts, o even a document like a PDF 

### cURL 

cURL allows us to preview the full HTTP request and response with `-v`: 

![](../Images/Pasted%20image%2020240115175407.png)

you can see even more info with more verbosity levels: 

![](../Images/Pasted%20image%2020240115175552.png)

## HTTP Headers 

HTTP headers pass info between the client and the server   
some headers are only used with either requests or responses  
headers can have one or multiple values, appended after the header name and separated by a colon  

header categories: 
- General headers
- Entity headers
- Request headers
- Response headers
- Security Headers 

### General headers 

used in both HTTP requests and responses   
contextual and are used to describe the message rather than its contents 

- `Date` - `Date: Wed, 16 Feb 2022 10:38:44 GMT` - date and time at which the message originated 
- `Connection` - `Connection: close` - dictates if the network connection should stay alive after the request finishes. Two commonly used values are `close` and `keep-alive` 

### Entity headers 

can be common for both the request and the response   
used to describe the content (entity)  
usually found in responses and POST or PUT requests 

- `Content-Type` - `Content-Type: text/html` - describe the resource being transferred. Automatically added by the browsers on the client-side and returned in the server response. The `charset` field denotes the encoding standard 
- `Media-Type` - `Media-Type: application/pdf` - similar to `Content-Type` and describes the data being transferred. Crucial role in making the server interpret the input. The `charset` field may also be used with this header 
- `Boundary` - `boundary="b4e4fbd93540"` - acts as a marker to separate content when there is more than one in the same message, for example boundaries will be placed within form data to separate different parts of the form 
- `Content-Length` - `Content-Length: 385` - size of the entity being passed. Server uses it to read data from the message body. Automatically generated by the browser and tools like cURL
- `Content-Encoding` - `Content-Encoding: gzip` - specifies the type of encoding 

### Request headers 

client sends request headers in an HTTP transaction   
used in an HTTP request and do not relate to the content of the message 

- `Host` - `Host: www.inlanefreight.com` - specify the host being queried for the resource. Domain name or an IP address. HTTP servers can be configured to host different websites which are revealed by the hostname, so this is important for enumeration because it can reveal the existence of other hosts on the target server
- `User-Agent` - `User-Agent: curl/7.77.0` - describe the client requesting the resources. Browser, version, OS, etc. 
- `Referer` - `Referer: http://inlanefreight.com/` - where the current request is coming from. Clicking a link from a google search would make `https://google.com` the referer. Trusting this header can be dangerous because it is easily manipulated 
- `Accept` - `Accept: */*` - describes which media types the client can understand. Can contain multiple media types separated by commas. `*/*` means that all media types are accepted 
- `Cookie` - `Cookie: PHPSESSID=basdfasdfs` - cookie value pairs in the format `name=value`. A cookie is a piece of data stored on the client-side and on the server, which acts as an identifier. Passed to the server per request, which maintains the client's access. Can also save user preferences or session tracking. Can be multiple cookies in a single header separated by semi-colon
- `Authorization` - `Authorization: BASIC casdrfwer` - Another method for the server to identify clients. After successful auth, the server returns a token unique to the client. Unlike cookies, tokens are stored only on the client-side and retrieved by the server by request. Multiple types of authentication 

### Response headers

can be used in HTTP response and do not related to the content  
certain headers like Age, Location, and Server are used to provide more context about the response  

- `Server` - `Server Apache/2.2.14 (Win32)` - info about the HTTP server, which processed the request. Can be used to gain info about the server like its version and enumerate it further 
- `Set-Cookie` - `Set-Cookie: PHPSESSID=basdfasdf` - cookies needed for client identification. Browsers parse cookies and store for future requests. 
- `WWW-Authenticate` - `WWW-AUTHENTICATE: BASIC realm="localhost"` - notifies client about the type of authentication required to access requested resource 

### Security headers 

class of response headers used to specify certain rules and policies to be followed by the browser while accessing the website 

- `Content-Security-Policy` - `Content-Security-Policy: script-src 'self'` - Dictates site's policy towards externally injected resources like JS code or script resources. Prevents XSS by only accepting resources from certain trusted domains 
- `Strict-Transport-Security` - `Strict-Transport-Security: max-age=3156000` - Prevents browser from accessing site over HTTP
- `Referrer-Policy` - `Referrer-Policy: origin` - dictates if the browser should include the value specified via the `Referer` header or not. Can help in avoiding disclosing sensitive URLs and info while browsing the site

### cURL

if we only wanted to see the response headers we can use `-I` to send a HEAD request and only display the response headers  
can also use `-i` to display both the headers and the response body  

you can set request headers with `-H` but some headers like `User-Agent` and `Cookie` have their own flags: 

`curl https://www.inlanefreight.com -A 'Mozilla/5.0'`

## HTTP Methods and Codes

there are multiple methods for accessing a resource, send info, forms, or files to a server   
these methods tell the server how to process the request we send and how to reply 

### Request methods 

some of the commonly used methods: 
- `GET` - requests a specific resource. Additional data can be passed to the server via query strings like `?param=value`
- `POST` - sends data to the server. Can handle multiple types of input like text, PDFs, and other binary data. Data is appended in the request body after the headers. 
- `HEAD` - requests headers that would be returned if a GET request was made. Doesn't return the request body, and usually used to check the response length before downloading resources 
- `PUT` - creates new resources on the server
- `DELETE` - deletes an existing resource on the webserver
- `OPTIONS` - returns info about the server such as the methods that it accepts 
- `PATCH` - applies partial modifications to the resource at the specified location

the availability of a particular method depends on the server and the app configuration   
most modern web apps rely on GET and POST but any that use a REST API also use PUT and DELETE   

### Response codes

status codes are used to tell the client the status of their request 

an HTTP server can return five types of response codes: 
- `1xx` - provides info and does not affect the processing of the request 
- `2xx` - returned when a request succeeds
- `3xx` - server redirects the client
- `4xx` - signifies improper requests from the client, like the resource doesn't exist or requesting a bad format
- `5xx` - a problem with the HTTP server itself

some commonly seen examples: 
- `200 OK` - successful request; response body usually contains resource
- `302 Found` - redirects client to another URL
- `400 Bad Request` - encountering malformed requests like requests without line terminators
- `403 Forbidden` - client doesn't have appropriate access to the resource; also when server detects malicious input from the user 
- `404 Not Found` - client requests a resource that doesn't exist 
- `500 Internal Server Error` - server can't process the request 

## GET 

browsers default to a GET request to obtain the remote resources hosted on a URL    
### HTTP basic auth

unlike usual login forms that use POST requests, basic HTTP authentication is handled directly by the webserver to protect specific pages and directories without directly interacting with the app  

![](../Images/Pasted%20image%2020240116134840.png)

trying to access the site with curl will show: 

![](../Images/Pasted%20image%2020240116135234.png)

with the `WWW-Authenticate: Basic realm="Access denied"` we can confirm that the page uses basic HTTP auth 

we can provide the credentials with `-u`: 

`curl -u admin:admin http://SERVER_IP:PORT`: 

![](../Images/Pasted%20image%2020240116135457.png)

we can also insert the credentials in the user info section of the URL: 

`curl http://admin:admin@SERVER_IP:PORT`

### HTTP authorization header

when we do `-v` on the previous commands we can see: 

![](../Images/Pasted%20image%2020240116135858.png)

where the `Authorization: Basic` value is the base64 value of `admin:admin`   
if we were using a modern method of auth like JWT, then the authorization would be of type `Bearer` and would contain a longer encrypted token 

we can manually set the authorization value by setting the header value in the curl command: 

`curl -H 'Authorization: Basic YWRtaW46YWRtaW4= http://SERVER_IP:PORT` 

![](../Images/Pasted%20image%2020240116140429.png)

these are a few methods to authenticate to the page  
most modern web apps use forms built with back-end logic to authenticate the users and then return a cookie to maintain their authentication 

### GET parameters

after logging in we can see a page that gives us city search results based on a term we provide: 

![](../Images/Pasted%20image%2020240116141247.png)

when the page returns our results it could be contacting a remote resource to obtain the info and display it to the page 

we can use the devtools network tab to monitor for any of these types of requests while using the site: 

![](../Images/Pasted%20image%2020240116145237.png)

we can see that the search form uses a GET request to search.php with the parameter search=le  

now we can use the same request in curl: 

![](../Images/Pasted%20image%2020240116145833.png)

if we were to copy the command from devtools it would contain a lot of headers that we might not need  

selecting the request in devtools and using `Copy as fetch` we can then also use this in the javascript console to repeat the request: 

![](../Images/Pasted%20image%2020240116150038.png)

## POST 

post requests can be used when apps need to transfer files or move the user parameters from the URL  

POST places user parameters in the HTTP request body which has 3 benefits: 
- lack of logging - post may transfer large files that would not be efficient for the server to log as part of the requested URL, which is what happens in GET 
- less encoding requirements - URLs are made to be shared which means they conform to characters that can be converted into letters. The request body can accept binary data so the only characters that need to be encoded are the ones that are used to separate parameters 
- more data can be sent - there is a max URL length that is different between browsers, servers, CDNs, and url shorteners. Generally, URLs can't handle a lot of data because they are limited to the length of the URL itself

### Login forms 

our target now has a login form to authenticate instead of HTTP basic auth  
using the network tab and filtering with the target IP we can see the requests being made when we login: 

![](../Images/Pasted%20image%2020240116160013.png)

when we look at the initial POST request we made to login we can see the info transmitted in the `Request` tab: 

![](../Images/Pasted%20image%2020240116160106.png)

we can do this request with curl using the `-X POST` flag: 

`curl -X POST -d 'username=admin&password=admin' http://SERVER_PORT:IP` 

![](../Images/Pasted%20image%2020240116160347.png)

many login forms will redirect us to a different page once authenticated and we can follow the redirection with `-L`

### Authenticated cookies 

if we are successfully authenticated then we should receive a cookie so our browsers can persist authentication  

using `-v` or `-i` we can see the `Set-Cookie` header with our cookie: 

![](../Images/Pasted%20image%2020240116160610.png)

with this cookie we should be able to access the site without doing the authentication process with the `-b` flag: 

![](../Images/Pasted%20image%2020240116160837.png)

we could also specify the cookie with the `-h` option: 

`curl -H 'Cookie: PHPSESSID=vl8pgosbfgc9g9nibtb84ov2t5' http://SERVER_IP:PORT` 

if we logout on the page and look in our `storage` in devtools we can see our cookies for the page: 

![](../Images/Pasted%20image%2020240116162059.png)

the cookie shown will not be valid to skip the authentication process because we just logged out, but if we go in and manually edit or replicate this cookie with the previously known cookie: 

![](../Images/Pasted%20image%2020240116162348.png)

then we can refresh the page and be already logged in: 

![](../Images/Pasted%20image%2020240116162417.png)

for many web apps, a valid cookie may be enough to get authenticated   
this can be essential for some web attacks like XSS

### JSON data 

for this target when we use the search form we can see that a POST request is sent: 

![](../Images/Pasted%20image%2020240116162607.png)

the data is in JSON so our request must have the specified `Content-Type` header to be `application/json` 

lets try to do this request with curl: 

![](../Images/Pasted%20image%2020240116164523.png)

## CRUD API 

APIs can also be used to perform requests that we did previously with PHP parameters 

### APIs 

many apis are used to interact with a database so that we would be able to specify the requested table and the requested row within our API query, then use the HTTP method to perform the operation needed  

if we had the `api.php` endpoint and wanted to update the city table we could do: 

`curl -X PUT http://SERVER_IP:PORT/api.php/city/london ...` 

### CRUD

in the previous example we could easily select the table and the row that we wanted to perform an operation on, then we could use HTTP methods to do different operations on that row

APIs perform 4 main operations on databases: 
- `Create` - `POST` - adds the specified data to the table 
- `Read` - `GET` - reads the specified entity from the table 
- `Update` - `PUT` - updates the data in the table 
- `Delete` - `DELETE` - removes the specified row from the table 

these 4 operations are mainly linked to CRUD but the same principles apply to REST APIs and many others   
user access control will limit what actions we can perform and what results we can see   

### Read