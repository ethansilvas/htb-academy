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

