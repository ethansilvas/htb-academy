
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

