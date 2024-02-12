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

