
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

