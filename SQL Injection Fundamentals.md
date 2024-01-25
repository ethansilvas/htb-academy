
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

