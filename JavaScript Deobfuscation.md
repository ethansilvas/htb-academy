
## Introduction 

code deobfuscation is an important skill for code analysis and reverse engineering   
often run into obfuscated code that wants to hide certain functionalities   

## Source Code

js performs any functions needed to run the site  

viewing the source code of the page with `Ctrl + U` or by right-clicking will reveal the HTML: 

![](Images/Pasted%20image%2020240122181935.png)

in this case we can see that the CSS is internally defined and that the JS file is in a separate `secret.js` file

viewing this file reveals a complicated and hard to read JS file: 

![](Images/Pasted%20image%2020240122182231.png)

## Code Obfuscation 

obfuscation is making code more difficult to read but allows it to function the same with possibly slower performance 

basic methods might be to turn the code into a dictionary of all the words and symbols in the code to rebuild it during execution  

use cases: 
- prevent code from being reused or copied 
- more difficult to reverse engineer 
- security layer when dealing with auth or encryption to prevent attacks on vulnerabilities (even through these shouldn't be done on the client side)

another common use is for malicious actions; common for attackers to obfuscate their code to prevent IDS/IPS tools from detecting their scripts 