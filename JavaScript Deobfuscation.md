
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

