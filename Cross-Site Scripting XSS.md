
## Introduction

among the most common web vulnerabilities are XSS attacks   
these take advantage of a flaw in user input sanitation to write JS code to the page and execute it on the client-side 

### What is XSS 

typical web app works by getting HTML code from the back-end server and rendering it on the client-side browser 

a malicious user can inject JS code in an input field for something like a comment or reply so that when another user visits the page they will execute the JS code unknowingly 

XSS solely executed on the client-side; do not directly affect the back-end server   
only affect the user who is executing the vulnerability   

direct impact on back-end server may be low but are common in web apps   
medium risk = low impact + high probability 

we aim to reduce medium risk like this: 

![](Images/Pasted%20image%2020240124110512.png)

### XSS attacks 

wide range of attacks since anything can be executed through the browser JS code   

basic example is having target send their session cookie to an attacker's web server   
another is having the target execute API calls that do things like change their password   
many other types that range from btc mining or displaying ads 

XSS attacks are limited to the browser's JS engine (like V8 in chrome)  
can't execute system-wide JS code  
modern browsers also limit to the same domain of the vulnerable site   
however there are still attacks like finding a binary vulnerability in a web browser (like a heap overflow) to then use XSS to execute JS exploit in browser that breaks out of browser's sandbox to execute code on target's machine 

### Types of XSS

three main types: 
- stored (persistent) XSS = most critical; user input is stored on the backend database and displayed upon retrieval (posts or comments)
- reflected (non-persistent) XSS = user input is displayed on the page after being processed by the backend server but is not stored (search result or error message) 
- DOM-based XSS = non-persistent; user input is directly shown in the browser and is completely processed on the client-side without reaching backend (through client-side http parameters or anchor tags)

