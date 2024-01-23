
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

## Basic Obfuscation 

code obfuscation usually not done manually; done by auto tools  
devs and malicious actors typically make their own tools to make it more difficult to deobfuscate 

with the example code: 

```javascript
console.log('HTB JavaScript Deobfuscation Module');
```

a basic way to reduce readability is `code minification` which is to have all the code in one line  
`javascript-minifier` is a good tool for this 

we can also obscure it with tools like `beautifytools`

![](Images/Pasted%20image%2020240123110815.png)

this type of obfuscation is called `packing`  
a packer is an obfuscation tool that attempts to convert all words and symbols of code into a list or dictionary and refer to them using the (p, a, c, k, e, d) function to re-build it   
usually contains an order in which the words and symbols were packed to know how to order them

notice though that we can still see the main strings in the example in plain text, which could reveal some functionality 

## Advanced Obfuscation

`obfuscator.io` will obfuscate even further to better hide cleartext 

![](Images/Pasted%20image%2020240123122105.png)

before we obfuscate we can set the string array encoding to base64: 

![](Images/Pasted%20image%2020240123122410.png)

with this set, our previous code will output to: 

```
var _0x1623bb=_0x56b5;function _0x56b5(_0x4f6573,_0x1829fb){var _0x1d9a1c=_0x1d9a();return _0x56b5=function(_0x56b538,_0x34c751){_0x56b538=_0x56b538-0x6c;var _0x25b209=_0x1d9a1c[_0x56b538];if(_0x56b5['XpcIiD']===undefined){var _0x4a97c2=function(_0x5924de){var _0x143151='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';var _0x4b70bc='',_0xe0a69a='';for(var _0x3343b6=0x0,_0x260bfe,_0xd782af,_0x5cb8a0=0x0;_0xd782af=_0x5924de['charAt'](_0x5cb8a0++);~_0xd782af&&(_0x260bfe=_0x3343b6%0x4?_0x260bfe*0x40+_0xd782af:_0xd782af,_0x3343b6++%0x4)?_0x4b70bc+=String['fromCharCode'](0xff&_0x260bfe>>(-0x2*_0x3343b6&0x6)):0x0){_0xd782af=_0x143151['indexOf'](_0xd782af);}for(var _0x39553a=0x0,_0xde9d01=_0x4b70bc['length'];_0x39553a<_0xde9d01;_0x39553a++){_0xe0a69a+='%'+('00'+_0x4b70bc['charCodeAt'](_0x39553a)['toString'](0x10))['slice'](-0x2);}return decodeURIComponent(_0xe0a69a);};_0x56b5['zDAGwd']=_0x4a97c2,_0x4f6573=arguments,_0x56b5['XpcIiD']=!![];}var _0x4551e2=_0x1d9a1c[0x0],_0x468f26=_0x56b538+_0x4551e2,_0x4318b6=_0x4f6573[_0x468f26];return!_0x4318b6?(_0x25b209=_0x56b5['zDAGwd'](_0x25b209),_0x4f6573[_0x468f26]=_0x25b209):_0x25b209=_0x4318b6,_0x25b209;},_0x56b5(_0x4f6573,_0x1829fb);}(function(_0x2a8135,_0x3c0b51){var _0x4ced41=_0x56b5,_0xb14f51=_0x2a8135();while(!![]){try{var _0x393a66=parseInt(_0x4ced41(0x6e))/0x1*(-parseInt(_0x4ced41(0x73))/0x2)+parseInt(_0x4ced41(0x6d))/0x3+-parseInt(_0x4ced41(0x74))/0x4+-parseInt(_0x4ced41(0x6c))/0x5*(-parseInt(_0x4ced41(0x72))/0x6)+-parseInt(_0x4ced41(0x75))/0x7+-parseInt(_0x4ced41(0x70))/0x8+parseInt(_0x4ced41(0x6f))/0x9*(parseInt(_0x4ced41(0x76))/0xa);if(_0x393a66===_0x3c0b51)break;else _0xb14f51['push'](_0xb14f51['shift']());}catch(_0x4128f4){_0xb14f51['push'](_0xb14f51['shift']());}}}(_0x1d9a,0xe5ccf),console[_0x1623bb(0x71)](_0x1623bb(0x77)));function _0x1d9a(){var _0x3a467a=['ntmXndeYmgvAwgL4Ea','mJy2ndC4oefiwKDWEq','ndK3mg9kBw1rBG','sfrciePHDMfty3jPChqGrgvVyMz1C2nHDgLVBIbnB2r1Bgu','nZa1oty1v2Ptz1bl','mZi4nZiXn210BLnZCq','muHzAKvmvq','nJK3mJnJsej2te8','mta4mdG2odblz3r0BhC','Bg9N','nM5Awfzxwa','mJe3mti1oe9Is1rSCq'];_0x1d9a=function(){return _0x3a467a;};return _0x1d9a();}
```

again this is much harder to read and running it provides the same results: 

![](Images/Pasted%20image%2020240123122855.png)

the further the code gets obfuscated the worse the performance gets 

some other encoders are `jj encode` and `aa encode` but these will likely impact performance  
these may be useful for avoiding web filters or restrictions though

## Deobfuscation 

just as there are tools to obfuscate, there are tools to deobfuscate

### Beautify 

minified JS code is often in one line and there are tools to properly reformat the code 

most basic way is to do this with the browser dev tools: 

![](Images/Pasted%20image%2020240123124255.png)

hitting the `{ }` button will pretty print all the code into proper formatting: 

![](Images/Pasted%20image%2020240123124355.png)

other online tools exist to do this like `prettier` and `beautifier`:

![](Images/Pasted%20image%2020240123124656.png)

in this example, secret.js is not only minified but also obfuscated to the better formatting only helps so much 

### Deobfuscate 

`unpacker` is a good online tool to try to deobfuscate: 

![](Images/Pasted%20image%2020240123125213.png)

**Note:** remember to not leave any empty lines before the script because it might affect the deobfuscation 

another way to unpack is to find the `return` value and use console.log() to print it instead of executing it: 

![](Images/Pasted%20image%2020240123125611.png)

### Reverse engineering 

when the code becomes more obfuscated and encoded it becomes much more difficult for auto tools to clean it up   
this becomes more true when custom obfuscation tools are used 

in these cases we will need to manually reverse engineer the code to understand how it was obfuscated 

secure coding 101 module goes through more advanced JS deobfuscation such as this

## Code Analysis 

now we have our de-minifying and deobfuscated code: 

```javascript
function generateSerial()
	{
	var flag="HTB
		{
		1_4m_7h3_53r14l_g3n3r470r!
	}
	";
	var xhr=new XMLHttpRequest();
	var url="/serial.php";
	xhr.open("POST",url,true);
	xhr.send(null)
}
```

from here we can start trying to understand what the code actually does 

we can see that it starts by defining a new `XMLHttpRequest` object to start sending a web request 

then it defines a url string as `/serial.php` which we can assume is pointing to the same domain as our target as no other domain is specified 

the next two lines use `.open()` and `.send()` to send a POST request with the url 

if we go back to our target site we don't see anything that might tell us what this could be used for: 

![](Images/Pasted%20image%2020240123132927.png)

now that we understand the code (and ignore the obvious text on the site) we might guess that the function is used to generate a serial number but the site might not actually use it yet as the developers might have kept it for future use 

now we can attempt to replicate the functionality of the code to see if it is handled on the server-side when we send the POST request ourselves   
if the function is enabled on the server-side we might uncover an unreleased functionality which has increased chances for bugs and vulnerabilities 

## HTTP Requests 

now lets attempt to replicate the found hidden code with curl  

curl will allow us to do things like: 

`curl -s http://SERVER_IP:PORT/ -X POST`

however POST requests usually contain data so we can specify this with `-d "param1=sample`

lets try replicating the POST request that the found code would do: 

![](Images/Pasted%20image%2020240123134129.png)

## Decoding 

from the previous output we seem to get a encoded output: 

`N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz`

many obfuscated code contains encoded text blocks that get decoded on execution 

the three most commonly used text encodings are: 
- base64 
- hex
- rot13

### Base64

typically used to reduce the use of special characters because any characters are represented in alpha-numeric characters in addition to + and / only   
even if input is in binary, the resulting base64 would only use these characters 

some ways to spot base64 encoding are 
- only alpha numeric 
- padding with = 
- length has to be in multiple of 4
- ex: if output is only of length 3, then the = is used to pad 

to encode into base64 we can use linux to pipe it into `base64`

`echo https://www.hackthebox.eu/ | base64`

we can then do the same with the `-d` option to decode it 

`echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d`

### Hex 

this will encode each character into its hex order in the ASCII table   
ex: a = 61, b = 62, ...

can use linux to see the full table with `man ascii`

we can spot hex because it will only contain hex characters which are only 16 characters: 0-9 and a-f

we can encode on linux with `xxd -p`

`echo https://www.hackthebox.eu/ | xxd -p`

then to decode we can use `-p -r`

### Caesar/rot13

caesar cipher shifts each letter by a fixed number 

there are variations of it like rot13 which shifts the characters 13 times forward 

easy to spot because characters are mapped to specific characters like `http://www` becomes `uggc://jjj` 

no command to do this in linux but we can do the following to create our own: 

```shell
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

and then the same one to decode: 

```shell
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

`rot13` is also an online tool to encode/decode 

### Other types of encoding 

some tools to determine what type of encoding is being used is `cipher identifier` 

some other types use encryption which is much harder to reverse engineer, especially if the decryption key is not stored in the script itself 


