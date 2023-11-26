
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

## Find Files and Directories 

`which` = returns the path to the file or link that should be executed 

determine if programs like curl, netcat, wget, python, gcc are available on the OS 

ex: `which python`

![](../Images/Pasted%20image%2020231124162331.png)

`find` = finds files and folders, but also filters the results 

`find <location> <options>`

![](../Images/Pasted%20image%2020231124164348.png)

`locate` = quicker way to search through system; uses a local database that has all info about existing files and folders, which find does not

update database with `sudo updatedb`

![](../Images/Pasted%20image%2020231124164549.png)

does not have as many filter options as find 

What is the name of the config file that has been created after 2020-03-03 and is smaller than 28k but larger than 25k:

![](../Images/Pasted%20image%2020231124165853.png)

How many files exist on the system that have the .bak extension? 

![](../Images/Pasted%20image%2020231124170111.png)

Locate the full path of the xxd binary:

![](../Images/Pasted%20image%2020231124170205.png)

## File Descriptors and Redirections 

file descriptor = indicator of connection maintained by the kernel to perform IO operations 
file handle in windows

1. Data stream for input = STDIN - 0
2. Data stream for output = STDOUT - 1
3. Data stream for output with errors = STDERR - 2

Running cat: 

![](../Images/Pasted%20image%2020231124172901.png)

first line is input = STDIN - FD 0
second line is output = STDOUT - FD 1

STDERR with find: 

![](../Images/Pasted%20image%2020231124173008.png)

only `/etc/shadow` is STDOUT - FD 1, all the others are STDERR - FD 2

can redirect FD 2 to /dev/null so that all errors go to the null device which discards all data 

`2>/dev/null`:

![](../Images/Pasted%20image%2020231124173211.png)

Can redirect to file with any output: 

![](../Images/Pasted%20image%2020231124173345.png)

or can specify with `1>results.txt`:

![](../Images/Pasted%20image%2020231124173513.png)

Take STDIN - FD 0 with < 

can take in input to `cat` with <: 

![](../Images/Pasted%20image%2020231124173632.png)

Redirecting output with > will create new file or overwrite existing file without confirmation

to append to a file use >>

![](../Images/Pasted%20image%2020231124173826.png)

With << can add standard input through stream 

Using the EOF function can read streaming input into cat and direct to a file stream.txt

![](../Images/Pasted%20image%2020231124174819.png)

Redirect with | to be used in other programs 

Use find to find all files with .conf in /etc/ and redirect STDERR to /dev/null, then grep search for all lines with "systemd":

![](../Images/Pasted%20image%2020231124175618.png)

Can then chain more pipes: 

![](../Images/Pasted%20image%2020231124175656.png)

How many files have the .log extension? 

![](../Images/Pasted%20image%2020231124175835.png)

## Filter Contents

`more` and `less` can be used to read files 

they are **pagers** that let you scroll through file in an interactive view 

`more /etc/passwd`:

![](../Images/Pasted%20image%2020231125175453.png)

`less /etc/passwd`:

![](../Images/Pasted%20image%2020231125175551.png)

less has more features and doesn't display output after using

`sort` can be used to sort output either alphabetically or numerically: 

![](../Images/Pasted%20image%2020231125175901.png)

`grep` can filter results like searching for which accounts have bash as default terminal: 

![](../Images/Pasted%20image%2020231125180148.png)

using `grep -v` will exclude any results that we want: 

![](../Images/Pasted%20image%2020231125180834.png)

this will exclude any results with false or nologin 

`cut` will remove specific delimiters 
`-d` = basically what to "split" on
`-f` = which index to take 

`-d":" -f1` = split on colon and take the first word (not 0 index):

![](../Images/Pasted%20image%2020231125182345.png)

`tr` can replace characters in a line with characters that we define 

`tr ":" " "`:

![](../Images/Pasted%20image%2020231125182456.png)

`column` displays results in tabular form with `-t`:

![](../Images/Pasted%20image%2020231125182658.png)

`awk` sorts results and grab info that we want

`awk '{print $1, $NF}'` = displays the first and last result on the line 

![](../Images/Pasted%20image%2020231125182931.png)

`sed` can replace text with regex

`s/` for substituting 
`/g` to replace all matches 

`sed s/bin/HTB/g`

![](../Images/Pasted%20image%2020231125183509.png)

`wc` for word count with `-l` to count lines:

![](../Images/Pasted%20image%2020231125183606.png)

Find the line with the username cryolite:

![](../Images/Pasted%20image%2020231125183913.png)

Get all the usernames:

![](../Images/Pasted%20image%2020231125184006.png)

Get the usernames and the UID:

![](../Images/Pasted%20image%2020231125184344.png)

Get the username cryolite and the UID:

![](../Images/Pasted%20image%2020231125184529.png)

Get the username cryolite and the UID separated by a comma:

![](../Images/Pasted%20image%2020231125185034.png)

Get the username cryolite, the UID, and the set shell separated by comma:

![](../Images/Pasted%20image%2020231125185210.png)

All usernames with the UID and set shells separated by comma: 

![](../Images/Pasted%20image%2020231125185253.png)

All usernames with the UID and set shells separated by comma and exclude any that have nologin and false:

![](../Images/Pasted%20image%2020231125185414.png)

All usernames with UID and set shells separated by comma and exclude any with nologin and count all the lines of the filtered output: 

![](../Images/Pasted%20image%2020231125185559.png)

Get how many services are listening on the target host system without counting localhost and only getting IPv4 connections: 

![](../Images/Pasted%20image%2020231125190709.png)

## Regular Expressions 

grouping operators: 

`(a)` = group parts of a regex 
`[a-z]` = define character classes; list of characters to search for 
`{1, 10}` = define quantifiers; number or range indicating how often a previous pattern should be repeated
`|` = OR 
`.*` = AND

OR operator with grep: 

`grep -E "(my|false)" /etc/passwd`

AND operator: 

`grep -E "(my.*false)" /etc/passwd`

Show all lines in /etc/ssh/sshd_config that do not contain the # character:

![](../Images/Pasted%20image%2020231125215208.png)

Search for all lines that contain a word that starts with Permit:

![](../Images/Pasted%20image%2020231125215730.png)

Search for all lines that contain a word ending with Authentication: 

![](../Images/Pasted%20image%2020231125215930.png)

Search for all lines containing the word Key:

![](../Images/Pasted%20image%2020231125220011.png)

Search for all lines beginning with Password and containing yes:

![](../Images/Pasted%20image%2020231125220213.png)

Search for all lines that end with yes:

![](../Images/Pasted%20image%2020231125220439.png)

## Permission Management 

execute permissions = permission to navigate to directory 
do not allow a user to execute or modify any files or contents in direcotry 

execute permissions for files = run files 

write = create, delete, rename 

apply read to all users: 

![](../Images/Pasted%20image%2020231125221843.png)

`chown` to change the owner and/or the group assignments of a file or directory 

change both owner and group to root:

![](../Images/Pasted%20image%2020231125222144.png)

SUID = Set user ID 
SGID = Set group ID 
allow users to run programs with the rights of another user 
ex: admin use to give their users special rights for certain apps or files 
's' instead of 'x'

S = execute bit is not set
s = execute bit is set

set SUID on file: 

![](../Images/Pasted%20image%2020231125223106.png)

**sticky bits** are a type of file permission in linux that can be set on directories 
extra layer of security for deletion and renaming of files within a directory 
typically used on directories shared by multiple users 

ex: admin can set sticky bit of directory to ensure that only owner of file, owner of directory, or the root user can delete or rename files within the directory 

setting sticky bit on directory: 

![](../Images/Pasted%20image%2020231125223032.png)

T = all other users that don't have x permissions (can't see contents of folder)
t = x permissions have been set

## User Management 

sudo - execute command as different user 
su - requests appropriate user creds via PAM and switches to that user ID, shell is then executed
useradd - create new user or update default new user info 
userdel - deletes user account and related files 
usermod - modifies user account
addgroup - adds a group to system 
delgroup - removes group from system 
passwd - changes user password 

Add a user with useradd: 

![](../Images/Pasted%20image%2020231126145843.png)

Lock an account with usermod: 

![](../Images/Pasted%20image%2020231126145822.png)

Change password with passwd: 

![](../Images/Pasted%20image%2020231126145904.png)

Run a command as a different user with su: 

![](../Images/Pasted%20image%2020231126150011.png)

