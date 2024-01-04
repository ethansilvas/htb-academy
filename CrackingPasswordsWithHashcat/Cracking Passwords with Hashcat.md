
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

