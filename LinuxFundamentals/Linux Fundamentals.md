
## Getting Help

Can either use `man` to view manual pages or help commands

`man curl`:

![](../Images/Pasted%20image%2020231122142704.png)

`curl --help`

![](../Images/Pasted%20image%2020231122142753.png)

Short version of help could be -h

`curl -h`

![](../Images/Pasted%20image%2020231122142839.png)

**apropos** = searches the descriptions for instances of a given word 

`apropos sudo`

[https://explainshell.com/](https://explainshell.com/)

## System Information

`hostname` = name of pc that we are using

![](../Images/Pasted%20image%2020231122144709.png)

`whoami` = get current username

one of the first parts of creating a reverse shell is knowing what user you have gained access to

![](../Images/Pasted%20image%2020231122144812.png)

`id` = expands on whoami and prints out group membership and IDs

useful to see what access users have and for sysadmins to audit account permissions/group membership

![](../Images/Pasted%20image%2020231122145029.png)

`uname` = info about the machine 

![](../Images/Pasted%20image%2020231122145205.png)

`uname -a` = all info about the machine; kernel name, hostname, kernel release, kernel version, machine hardware name, and OS 

![](../Images/Pasted%20image%2020231122145233.png)

`uname -p` - processor type
`uname -i` hardware platform 

![](../Images/Pasted%20image%2020231122145512.png)

Some of this info like kernel release can be used to lookup "kernel_release exploit" to know how we can attack the target

### Logging in via SSH 

SSH lets you access and execute commands or actions on remote computers 

The basic command is `ssh [username]@[IP]`

First, SSH to user htb-student at the target IP: 

![](../Images/Pasted%20image%2020231122150528.png)

What is the machine hardware name? 

x86_64:

![](../Images/Pasted%20image%2020231122153708.png)

What shell is specified for the user? 

/bin/bash:

![](../Images/Pasted%20image%2020231122153751.png)

What kernel version is installed? 

4.15.0:

![](../Images/Pasted%20image%2020231122153816.png)

What is the network interface that MTU is set to 1500?

ens 192: 

![](../Images/Pasted%20image%2020231122153617.png)

## Navigation

`pwd` = get current directory 

![](../Images/Pasted%20image%2020231122164513.png)

`ls` = list contents inside directory 

![](../Images/Pasted%20image%2020231122164535.png)

`ls -l` = get extra info on each file and directory 

![](../Images/Pasted%20image%2020231122164631.png)

the order of info goes
- permissions
- number of hard links to file 
- owner
- group owner 
- size of file or number of blocks used to store 
- date and time 
- dir name

`ls -la` to list all files in dir

![](../Images/Pasted%20image%2020231122170110.png)

`&&` to do multiple commands 

![](../Images/Pasted%20image%2020231122170750.png)

`ls -li` to get index number of files and directories 

![](../Images/Pasted%20image%2020231122171313.png)

## Working with Files and Directories

Creating files and directories with `touch` and `mkdir`:

![](../Images/Pasted%20image%2020231122180138.png)

Create multiple child directories in one command, `mkdir -p filepath` and then look at the whole structure using `tree`:

![](../Images/Pasted%20image%2020231122180523.png)

Copy a file to another directory: 

![](../Images/Pasted%20image%2020231122190151.png)

![](../Images/Pasted%20image%2020231122190201.png)

Getting the last modified file with `ls -lt`:

![](../Images/Pasted%20image%2020231122192058.png)

Getting the inode number of files with `ls -i`

![](../Images/Pasted%20image%2020231122192123.png)

## Editing Files

can create a new file with `nano notes.txt`



