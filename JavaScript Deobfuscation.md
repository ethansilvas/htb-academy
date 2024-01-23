
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

