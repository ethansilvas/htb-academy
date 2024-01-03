
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

