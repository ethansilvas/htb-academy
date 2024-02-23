# Web Attacks

## Introduction to Web Attacks

web attacks are the most common types of attacks against companies   

attacking external-facing web apps can lead to compromise of internal network which can lead to stolen assets or disrupted services   
even if the org doesn't use external facing web apps they will still likely use internal ones or external facing API endpoints, both of which are still vulnerable to the same types of attacks 

### HTTP verb tampering 

these attacks exploit web servers that accept many HTTP verbs and methods   
can be exploited by sending malicious requests using unexpected methods which may lead to bypassing authentication or security controls against other web attacks   

these are one of many other HTTP attacks that can be used to exploit web server configs by sending malicious HTTP requests 

### Insecure direct object references (IDOR)

among the most common web vulnerabilities and can lead to accessing data that should not be accessible by attackers   
so common because of a lack of solid access control system on backends   

web apps store users files and info, which may use sequential numbers or user IDs to identify them   
suppose the app exposes direct access to these files, in this case we can then access other user's files and info by simply guessing or calculating their file IDs 

### XML external entity (XXE) injection 

many web apps parse XML data; suppose they use outdated XML libraries to parse and process user XML input data, then it would be possible to send malicious files to disclose local files   
these files may contain sensitive info or source code   

can also be leveraged to steal the hosting server's credentials which could compromise the entire server and allow for RCE 

