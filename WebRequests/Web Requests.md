
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

