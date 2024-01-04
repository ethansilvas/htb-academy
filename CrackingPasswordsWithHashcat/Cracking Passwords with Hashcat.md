
## Introduction 

password cracking = offline brute force attacks

many passwords are stored with cryptographic algorithms to not store/send plaintext 

during an assessment, we will often find a password hash that we need to attempt to crack offline 

## Hashing vs Encryption 

hashing = converting text to a string unique to that input  
usually returns same length of string  
one-way process  

hashing can have different purposes: 
- MD5 and SHA256 are typically used to verify file integrity 
- PBKDF2 are used to hash passwords before storage 

some hashing functions are keyed, meaning that they use another secret to create the hash  
HMAC - hash-based message authentication code; acts as a checksum to verify if a message has been tampered with during transmission   

since hashing is a one-way process, the way that we can crack these hashes is to use a list of predetermined words and calculate their hashes 

there are mainly 4 different algorithms that can be used to protect passwords on Unix systems: 
- SHA-512 
- Blowfish 
- BCrypt
- Argon2 

SHA-512 = converts long string of characters into has value  
fast and efficient but has vulnerable to many rainbow table attacks 

blowfish = symmetric block cipher that encrypts passwords with a key  
more secure than SHA-512 but also a lot slower 

bcrypt = slow hash function to make it harder for potential hackers to guess or make rainbow table attacks 

argon2 = modern and secure algorithm designed for password hashing systems  
multiple rounds of hashing and a large amount of memory to make it harder for attackers  
one of the most secure algorithms because of high time and resources needed 

salt = random piece of plaintext added before hashing it  
increases the hashing time but does not prevent brute forcing altogether  

if we look at the md5 hash for "p@ssw0rd": 

![](../Images/Pasted%20image%2020240103122236.png)

then we can add random salt and compare: 

![](../Images/Pasted%20image%2020240103122321.png)

a completely new hash is generated and attackers will need to spend extra time to try to guess the salt 

another thing to consider for algorithms is how vulnerable they are to collisions, which is when two different plaintext values generate the same hash  
MD5 has been vulnerable to collisions  

### Encryption 

encryption = converting data into a format where the original content is not accessible  
encryption is a reversable process; possible to decrypt ciphertext to get original data  
one of two types: symmetric and asymmetric 

#### Symmetric encryption

use a key or secret to encrypt the data and use the same key to decrypt 

XOR is a simple example: 

![](../Images/Pasted%20image%2020240103123522.png)

![](../Images/Pasted%20image%2020240103123532.png)

in the example above the plaintext is p@ssw0rd and the key is secret  
anyone that has the key can decrypt any of its ciphertext  

some examples of symmetric algorithms: 
- AES
- DES
- 3DES
- Blowfish 

these are vulnerable to attacks like bruteforcing, frequency analysis, padding oracle attack, etc. 

#### Asymmetric encryption 

two keys, public and private, are used to encrypt and decrypt 

the public key can be shared with anyone that wants to encrypt info and pass it securely to the owner  
only the owner has the private key and can then decrypt the data encrypted with their public key 

some examples of asymmetric algorithms are: 
- RSA 
- ECDSA
- Diffie-Hellman 

one of the most prominent uses of asymmetric encryption is HTTPS, which uses SSL/TLS  
when a client connects to a servers hosting an HTTPS website, a public key exchange occurs  

generate an MD5 hash of HackTheBox123!: 

![](../Images/Pasted%20image%2020240103124600.png)

create an XOR cipher of the password opens3same using the key academy: 

![](../Images/Pasted%20image%2020240103124805.png)

## Identifying Hashes 

the length of a hash can be used to map it to the algorithm that created it 

hashes of 32 characters can be an MD5 or NTLM hash 

sometimes hashes are stored in certain formats like `hash:salt` or `$id$salt$hash`

`2fc5a684737ce1bf7b3b239df432416e0dd07357:2014` is a SHA1 hash with the salt of 2014

ids of hashes can be used to map to the hashing algorithm as well: 
- `$1$` = MD5
- `$2a$` = blowfish 
- `$2y$` = blowfish with correct handling of 8-bit characters 
- `$5$` = SHA256
- `$6$` = SHA512

open and closed source software can use many different forms of hashing  

### Hashid

hashid is a python tool that can be used to detect various kinds of hashes:

![](../Images/Pasted%20image%2020240103131927.png)

you can also provide a file of hashes for hashid to identify line by line 

it can also provide the corresponding hashcat hash mode with `-m`: 

![](../Images/Pasted%20image%2020240103132155.png)

### Context is important 

not always possible to identify the algorithm based on the hash 

additional context is useful such as: 
- was it found via active directory or from a windows host
- was it found through the exploitation of a SQL injection 

this context can narrow down the possible hash types, and therefore the hashcat hash mode needed to attempt to crack it 

hashcat provides a [reference](https://hashcat.net/wiki/doku.php?id=example_hashes) that maps hash modes to example hashes  
this can be helpful because hashid may return many results for a given hash, but the hashcat examples can tell us that it is indeed a certain hash mode 

identify the following hash: `$S$D34783772bRXEx1aCsvY.bqgaaSu75XmVlKrW9Du8IQlvxHlmzLc`

![](../Images/Pasted%20image%2020240103132813.png)

![](../Images/Pasted%20image%2020240103132912.png)

## Hashcat Overview 

`-a` for attack mode  
`-m` for hashcat mode 

attack modes: 
- 0 = straight 
- 1 = combination 
- 3 = brute-force 
- 6 = hybrid wordlist + mask
- 7 = hybrid mask + wordlist 

you can also view the example hashes with: `hashcat --example-hashes | less`

the benchmark test or performance test for a hash type can be performed with `-b`: 

![](../Images/Pasted%20image%2020240103145005.png)

hashcat has two main ways to optimize speed: 
- optimized kernels = `-O` which means enable optimized kernels (limits password length)
	- password length generally is 32, which most wordlists won't even hit 
	- can take estimated time down from days to hours 
	- recommended to always run with `-O` first and then without if your GPU is idle 
- workload = `-W` which means enable a specific workload profile
	- default number is 2, but if you want to use pc while hashcat is running, then use 1 
	- if you plan on your pc only running hashcat then use 3 

`--force` should be avoided  
this will appear to make hashcat work on certain hosts, but what it does is disable safety checks, mutes warnings, and bypasses problems  
this can lead to false positives, false negatives, malfunctions, etc.  
if it is not working without --force, then the root cause should be found instead of using --force

## Dictionary Attack

hashcat has 5 different attack modes  
most straightforward is dictionary 

hashcat attack type 0 = straight or dictionary attack  
reads from a wordlist and tries to crack the supplied hashes 

`hashcat -a 0 -m <hash type> <hash file> <wordlist>`

here we set up a SHA-256 hash of !academy: 

![](../Images/Pasted%20image%2020240103165135.png)

and hashcat is able to crack it with rockyou.txt: 

![](../Images/Pasted%20image%2020240103165205.png)
![](../Images/Pasted%20image%2020240103165220.png)

Bcrypt is based on blowfish, uses salt, and can have many rounds of the algorithm applied  
it is very resistant to password cracking even with a large password cracking rig 

attempting to crack the same hash with rockyou will take over 1.5 hours, compared to the 4 second long SHA-256 crack  

you can view crack time by pressing the `s` key while hashcat is running

applying the algorithm more and more times will increase the cracking time exponentially 

in the case of hashes like bcrypt, it is often better to use smaller, more targeted, wordlists

even weaker passwords with stronger hashing algorithms can be more difficult to crack just based on the algorithm  
however this doesn't mean that a weak password with a stronger hashing algorithm is more secure 

cracking rigs with many GPUs make the processing time much faster 

now lets try to crack the hash `0c352d5b2f45217c57bef9f8452ce376`

judging by the size of it, it appears to be an MD5 hash so I will specify the mode as 0, add the hash to hash.txt, and use rockyou.txt: 

![](../Images/Pasted%20image%2020240103171716.png)

![](../Images/Pasted%20image%2020240103171745.png)

## Combination Attack 

a combination attack uses two wordlists as input and creates combos from them  
this is useful because often users will simply combine two words together, thinking it's more safe 

you can see the different combos that it creates with `--stdout`: 

`hashcat -a 1 --stdout file1 file2`

the full combo attack syntax is: 

`hashcat -a 1 -m <hash type> <hash file> <wordlist 1> <wordlist 2>`

first we create a md5 hash of secretpassword:

![](../Images/Pasted%20image%2020240103190301.png)

then use the following wordlists: 

![](../Images/Pasted%20image%2020240103190416.png)

we can then crack the password with attack method 1: 

![](../Images/Pasted%20image%2020240103190437.png)

now lets find the cleartext of the md5 hash `19672a3f042ae1b592289f8333bf76c5`

first we create our wordlists: 

![](../Images/Pasted%20image%2020240103190648.png)

then we can add our hash to a file and crack it: 

![](../Images/Pasted%20image%2020240103190847.png)
![](../Images/Pasted%20image%2020240103190900.png)

## Mask Attack

mask attack are used to generate words matching a specific pattern  
this is useful when the password length or format is not known 

mask can be created from static characters, ranges of characters, or placeholders

placeholders: 
- ?| = lower-case ASCII letters (a-z)
- ?u = upper-case ASCII letters (A-Z)
- ?d = digits (0-9)
- ?h = 0123456789abcdef
- ?H = 123456789ABCDEF
- ?s = special characters (`space!"#$'()*+,-./:;<=>?@[]^_`)
- ?a = ?|?u?d?s
- ?b = 0x00 - 0xff

these placeholders can be combined with options `-1` to `-4` which can be used for custom placeholders: 

![](../Images/Pasted%20image%2020240103205325.png)

consider a company inlane freight which has passwords with the scheme `ILFREIGHT<userid><year>`

the mask `ILFREIGHT?l?l?l?l?l20[0-1]?d` can be used to crack passwords where:  
- `?l` is a letter 
- `20[0-1]?d` will include all years from 2000 to 2019

first lets make a hash of the password: 

![](../Images/Pasted%20image%2020240103210547.png)

![](../Images/Pasted%20image%2020240103210511.png)

then lets craft a mask attack command: 

![](../Images/Pasted%20image%2020240103211043.png)

here we use the following parameters: 
- `-a 3` for attack mode 3 for brute force mask attack 
- `-m 0` for mode 0 which is MD5
- `-1 01` create a custom charset placeholder for just the numbers 0 and 1, this is then used in the mask string after "20" so hashcat will only look for years that start with 200 or 201

we are then able to crack the password: 

![](../Images/Pasted%20image%2020240103211410.png)

`--increment` can be used to increment the mask automatically with a length limit of `--increment-max`

to find the password from a hash I start by adding it to a file and creating my mask command: 

![](../Images/Pasted%20image%2020240103212650.png)

then the password can be found: 

![](../Images/Pasted%20image%2020240103212728.png)

## Hybrid Mode

hybrid mode is a variation of the combinator attack where multiple modes can be used together  
this can be useful to create very customized wordlists  
particularly useful when you have a good idea of what the orgs password policy is 

mode 6 

using the password football1$ lets create a wordlist and a mask: 

![](../Images/Pasted%20image%2020240103213053.png)

now we can make our command, and in it we will specify the rockyou.txt wordlist and a mask of `?d?s` which hashcat will append to the end of each word in rockyou.txt: 

![](../Images/Pasted%20image%2020240103213337.png)

![](../Images/Pasted%20image%2020240103213409.png)

if we wanted to prepend characters we can instead use attack mode 7, for example: 

`hashcat -a 7 -m 0 hybrid_hash_prefix -1 01 '20?1?d' rockyou.txt`

now lets try to crack the plaintext of `978078e7845f2fb2e20399d9e80475bc1c275e06`

first lets find our what type of hash it is: 

![](../Images/Pasted%20image%2020240103214039.png)

it appears to be a SHA-1 hash so now lets try to use rockyou.txt with the supplied mask of ?d?s:

![](../Images/Pasted%20image%2020240103214619.png)

we get the password from appending the mask: 

![](../Images/Pasted%20image%2020240103214645.png)

## Creating Custom Wordlists

### Crunch

crunch is an open source tool to create wordlists based on parameters like word length, char set, or pattern  
it can generate permutations and combinations 

basic crunch syntax: 

`crunch <min length> <max length> <charset> -t <pattern> -o <outputfile`

`-t` is used to specify the pattern for passwords 
- @ = lower case characters
- , = upper case 
- % = numbers
- ^ = symbols 

we can generate a wordlist with words of length 4-8 characters with the default charset: 

`crunch 4 8 -o wordlist`

for a password of form `ILFREIGHTYYYYXXXX` where YYYY is the year and XXXX is the employee id, we can create a list of these passwords like so: 

`crunch 17 17 -t ILFREIGHT201%@@@@ -o wordlist` 

if we know something like a birthdate, 10/03/1998, we can use `-d` to specify the amount of times a character can be repeated: 

`crunch 12 12 -t 10031998@@@@ -d 1 -o wordlist`

### CUPP

create personalized wordlists based on OSINT about the target 

`python3 cupp.py -i`

offers leet mode which uses combos of letters and numbers in common words 

can also fetch common names form online databases using `-l`

### KWPROCESSOR 

kwprocessor creates wordlists with keyboards walks  
keyboard walks follow patterns on the keyboard, like "qwertyasdfg"  

needs to be installed manually: 

```shell
git clone https://github.com/hashcat/kwprocessor
cd kwprocessor
make
```

various options are used based on the directions that a user could choose on keyboard  
for example `--keywalk-west` specifies movement towards the west from the base character 

commands take in: 
- base characters = character set the pattern will start with
- keymap = maps locations of keys on language-specific keyboard layouts 
- route = pattern to be followed by passwords, for example 222 will be 2 east, 2 south, 2 west from the base character 
	- if base character is T then generated route would be "TYUJNBV"

an example command: 

`kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route`

`-s` will add shift 

### Princeprocessor 

an efficient password guessing algorithm to improve password cracking rates  

takes in a wordlist and creates chains of words taken from the wordlist: 

```
dog 
cat
ball
```

```shell-session
dog
cat
ball
dogdog
catdog
dogcat
catcat
dogball
catball
balldog
ballcat
ballball
dogdogdog
catdogdog
dogcatdog
catcatdog
dogdogcat
<SNIP>
```

princeprocessor install: 

```shell
wget https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z
7z x princeprocessor-0.22.7z
cd princeprocessor-0.22
./pp64.bin -h
```

`--keyspace` can be used to find the number of combos produced from the wordlist: 

`./pp64.bin --keyspace < words`

you can form a wordlist with: 

`./pp64.bin -o wordlist.txt < words`

by default it only creates words up to 16 in length, and you can change that with `--pw-min` or `--pw-max`:

`./pp64.bin --pw-min=10 --pw-max=25 -o wordlist.txt < words`

you can also specify the number of elements per word with `--elem-cnt-min` and `--elem-cnt-max`:

`./pp64.bin --elem-cnt-min=3 -o wordlist.txt < words`

the above command will output words with three elements or more, such as "dogdogdog"

### CeWL

cewl will spider and scrape a website and creates a list of the words that are present 

you can find words related to a company in their blogs, testimonials, and product descriptions 

the general syntax is: 

`cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url>`

you can also extract emails with `-e`: 

`cewl -d 5 -m 8 -e http://inlanefreight.com/blog -w wordlist.txt`


