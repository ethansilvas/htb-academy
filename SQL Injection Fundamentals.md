
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

