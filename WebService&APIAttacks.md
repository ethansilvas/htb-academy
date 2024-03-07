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



