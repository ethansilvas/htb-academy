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
