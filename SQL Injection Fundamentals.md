
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

