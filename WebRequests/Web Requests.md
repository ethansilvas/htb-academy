
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


