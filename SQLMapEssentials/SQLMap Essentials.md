
## SQLMap Overview 

sqlmap is an open-source pen testing tool that automates the detection and exploitation of sql injection flaws 

`python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5`

contains options and switches for: 
- target connection 
- enumeration
- database content retrieval 
- injection detection 
- optimization
- file system access
- fingerprinting 
- protection detection and bypass using "tamper" scripts
- execution of the OS commands 

you can install with: 

`sudo apt install sqlmap`

manual installation: 

`git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev'

then you can run sqlmap with: 

`python sqlmap.py`

there are many supported databases: 

![](../Images/Pasted%20image%2020240105185232.png)

you can see the supported SQL injections with `sqlmap -hh`

BEUSTQ technique characters: 
- `B` = boolean-based blind 
- `E` = Error-based 
- `U` = union query-based 
- `S` = stacked queries 
- `T` = time-based blind 
- `Q` = inline queries

### Boolean-based blind SQL injection 

`AND 1=1`

sqlmap exploits boolean-based blind sql injection through the differentiation of TURE from FALSE query results   
retrieving 1 byte of info per request  
differentiation is based on server responses to see if it returned TRUE of FALSE   
could be from raw response content, HTTP codes, page titles, filtered text, etc. 

TRUE = generally based on responses having none or small difference to regular server response  
FALSE = substantial differences form regular server response  

boolean-based blind SQL injection is most common SQLi type in web apps 

### 