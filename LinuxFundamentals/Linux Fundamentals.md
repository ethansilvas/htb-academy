
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

## Package Management 

packages = archives that contain binaries of software, config files, info about dependencies and keep track of updates and upgrades 

- Package downloading 
- Dependency resolution 
- standard binary package format 
- common installation and config locations 
- additional system-related configuration and functionality 
- quality control 

software must be available as package 

created, offered, and maintained centrally under Linux distributions, software is integrated directly into the system and directories are distributed throughout the system 

will be able to detect when packages are required for proper functioning of the package that has not yet been installed 

if installed software has been deleted, package management system retakes the package's info, modifies it based on its configuration and deletes the files 

package management systems:
- dpkg - debian packages 
- apt - cli for the package management system
- aptitude - alternative to apt
- snap - snap packages; latest apps and utils for cloud, servers, desktops, and IoT 
- gem - front-end to RubyGems; ruby package manager
- pip - python
- git - distributed revision control system

### APT 

debian based linux uses APT 

package = archive file containing .deb files 

dpkg = install programs associated with .deb file 

APT makes it easier to deal with dependencies, as compared to downloading standalone .deb files 

most linux distros utilize the most stable or main repo for package repos 

can view the contents of `/etc/apt/sources.list` to see the list of repositories being used 

parotOS = `/etc/apt/sources.list.d/parrot.list`

APT cache = provide info about packages installed on our system offline 

`apt-cache search impacket` = find all Impacket related packages:

![](../Images/Pasted%20image%2020231126172112.png)

list all installed packages with `apt list --installed`: 

![](../Images/Pasted%20image%2020231126172234.png)

can search for missing packages and install them: 

![](../Images/Pasted%20image%2020231126172336.png)

-y will auto say yes to all prompts

## Git 

making a directory and then cloning into it:

![](../Images/Pasted%20image%2020231126173247.png)

### DPKG

we can download the programs and the tools from the repositories separately 

use `wget` to download strace for ubuntu:

![](../Images/Pasted%20image%2020231126173404.png)

now can use both apt and dpkg to install it

using dpkg to install the previously downloaded strace debian file: 

![](../Images/Pasted%20image%2020231126173624.png)

## Service and Process Management 

two types of services:
- internal = services required at system startup 
- services installed by user = includes all server services 

run in the background without user interaction = daemons 

daemons identified by 'd' at the end of the program name

sshd or systemd 

most linux distros use systemd 

systemd = init process started first (process ID 1)
monitors and takes care of the orderly starting and stopping of other services 

`/proc/` = can view all processes and their assigned PID 

PPID = parent process ID 

`systemctl` and `update-rc.d` = manage SysV init script links 

### Systemctl

start OpenSSH:

![](../Images/Pasted%20image%2020231127202355.png)

check status: 

![](../Images/Pasted%20image%2020231127202612.png)

add OpenSSH to the SysV script so that it runs after startup:

![](../Images/Pasted%20image%2020231127203402.png)

can then use process status or `ps` to check the status of it: 

![](../Images/Pasted%20image%2020231127203453.png)

can also use systemctl to list all services:

![](../Images/Pasted%20image%2020231127203722.png)

if services don't start because of error you can see the logs with journalctl: 

![](../Images/Pasted%20image%2020231127203800.png)

### Kill a process

processes can be: 
- running
- waiting (for an event or system resource)
- stopped 
- zombie (stopped but still has an entry in the process table)

processes can be controlled with: 
- kill 
- pkill 
- pgrep
- killall

to interact with a process you have to send a signal to it, you can view all signals with: 

![](../Images/Pasted%20image%2020231127204440.png)

most commonly used signals are: 
- 1 SIGHUP = sent to process when terminal that controls it is closed 
- 2 SIGINT = sent when user presses CTRL+C in the controlling terminal to interrupt it 
- 3 SIGQUIT = when user presses CTRL+D to quit 
- 9 SIGKILL = immediately kill a process with no clean-up operations
- 15 SIGTERM = program termination
- 19 SIGSTOP = stop the program, can't be handled anymore
- 20 SIGTSTP = when user presses CTRL+Z to request for a service to suspend, can handle after

killing a ping process: 

![](../Images/Pasted%20image%2020231127205255.png)

### Background a process

sometimes need to put scan or process we just started in background to continue using the current session to interact with the system or start other processes

can do this with CTRL+Z

can view all of the background processes with `jobs`:

![](../Images/Pasted%20image%2020231127205702.png)

suspended processes will not be executed further but we can keep it running in the background with `bg`:

![](../Images/Pasted%20image%2020231127210042.png)

`fg` = brings process to the foreground: 

![](../Images/Pasted%20image%2020231127210316.png)

putting an `&` at the end of command will automatically run the process in the background: 

![](../Images/Pasted%20image%2020231127210528.png)

### Execute multiple commands

three ways to run several commands: 
- ;
- &&
- |

`;` will separate commands and executes commands ignoring each other:

![](../Images/Pasted%20image%2020231127211509.png)

![](../Images/Pasted%20image%2020231127211542.png)

`&&` = will not run after errors:

![](../Images/Pasted%20image%2020231127211627.png)

`|` will depend on no errors and depend on the results of the previous command

List all units of services and find a specific one: 

![](../Images/Pasted%20image%2020231127212111.png)

## Task Scheduling

task scheduling = schedule and automate tasks in linux 

run tasks at specific times or within specific frequencies without having to start them manually 

examples:
* auto update software
* running scripts
* cleaning databases
* automating backups 

### Systemd

used to start processes and scripts at a specific time 

can also specify events and triggers that will trigger a specific task 

1. create a timer
2. create a service 
3. activate the timer

Create a timer with mkdir:

![](../Images/Pasted%20image%2020231127215704.png)

timer scripts needs:
- Unit = description for the timer
- Timer = when to start the timer and when to activate it 
- Install = where to install the timer 

![](../Images/Pasted%20image%2020231127215557.png)

OnBootSec = how to run on boot
OnUnitActiveSec = change how often to run the script

Create a service file:

![](../Images/Pasted%20image%2020231127215825.png)

![](../Images/Pasted%20image%2020231127220037.png)

multi-user.target= the unit system that is activated when starting a normal multi-user mode
defines the services that should be started on a normal system startup

then let systemd read the folders again to include the changes:

![](../Images/Pasted%20image%2020231127220156.png)

use systemctl to start the service and enable the autostart:

![](../Images/Pasted%20image%2020231127220245.png)

service is now viewable:

![](../Images/Pasted%20image%2020231127220640.png)

### Cron

can also schedule and automate processes; allows users to execute tasks at a specific time or within specific intervals 

to setup cron daemon, need to store the tasks in a file called `crontab` and tell the daemon when to run the tasks 

create file with `crontab -e`

### Systemd vs Cron

systemd you need to create a timer and services script that tells the OS when to run the tasks 

Cron you need to create a crontab file that tells the cron daemon when to run the tasks

use `systemctl show` to view specific services

## Network Services 

### SSH 

secure transmission of data and commands over a network 

manage remote systems and securely access remote systems for commands or file transfers

installing OpenSSH: 

![](../Images/Pasted%20image%2020231129153612.png)

check if the server is running: 

![](../Images/Pasted%20image%2020231129153656.png)

using `ssh host@IP` you can securely access remote systems when performing network audit

configure and customize openssh with `/etc/ssh/sshd_config`

### NFS 

network file system = network protocol to store and manage files on remote systems as if they were stored on the local system 

multiple servers 
- NFS-UTILS ubuntu
- NFS-Ganesha solaris
- OpenNFS redhat

used to share and manage resources efficiently, real-time file transfer, and support for multiple users accessing data simultaneously 

can use like FTP 

install nfs: 

![](../Images/Pasted%20image%2020231129154846.png)

check if server is running: 

![](../Images/Pasted%20image%2020231129154914.png)

configure NFS with `/etc/exports` = which directories should be shared and the access rights for users/systems 

![](../Images/Pasted%20image%2020231129160538.png)

- rw = read write
- ro = read only
- no_root_squash = prevent root user on client from having only normal user rights
- root_squash = root user on client only has rights of normal user 
- sync = sync transfer of data to ensure changes are only transferred after they have been saved
- async = transfers data async which makes it faster but can lead to inconsistencies if changes have not been fully committed 

can add a NFS share folder with:

```
mkdir nfs_sharing
echo '/home/user/nfs_sharing' hostname(rw,sync,no_root_squash)' >> /etc/exports
cat /etc/exports | grep -v "#"
```

after creating the share it needs to be mounted: 

```
mkdir ~/target_nfs
mount 10.129.12.17:/home/test/dev_scripts ~/target_nfs
tree ~/target_nfs
```

now the contents of the dev_scripts directory on the NFS server will be accessible at ~/target_nfs on the local machine

### Web Servers 

provide data and docs or other applications and functions over the internet 

HTTP to send data to clients such as web browsers and receive requests from them 

popular web servers are: 
- apache
- nginx 
- ligttpd
- caddy

can be used to perform file transfers or phishing attacks by hosting a copy of the target page on our own server then attempting to steal user creds

install apache web server:

![](../Images/Pasted%20image%2020231129163601.png)

specify which folders can be accessed with `/etc/apache2/apache2.conf` 

```
<Directory /var/www/html>  
	Options Indexes FollowSymLinks  
	AllowOverride All  
	Require all granted  
</directory>
```

- users can use the indexes and FollowSymLinks options
- changes in the directory can be overridden with AllowOverride All 
- require all granted grants all users access to this directory 

with these options we could put files in /var/www/html folder and use wget or curl or other applications to download these files on the target system from the web server

`.htaccess` file can be used to customize individual settings at the directory level  
can create this in the directory needed  
directory level settings such as access controls  

can add modules like mod_rewrite, mod_security, or mod_ssl to enhance security 

### Python web server

alternative to apache

can be used to host a single folder with a single command to transfer files to another system

after installing python you can start the web server on the TCP 8000 port and host the current directory:

![](../Images/Pasted%20image%2020231129164657.png)

can also host a specific directory: 

![](../Images/Pasted%20image%2020231129165949.png)

can also specify port with `-p`

### VPN 

let us connect to a network as if we were directly in it 

popular VPN servers for linux
- OpenVPN
- L2TP/IPsec
- PPTP
- SSTP
- SoftEther

can also be used as a pen tester to connect to internal networks 

install with `sudo apt install openvpn -y`

customize with the `/etc/openvpn/server.conf` file  
can enable encryption, tunneling, traffic shaping, etc

to connect to an openvpn server we use the`.ovpn` file from the server and save it to our system:

`sudo openvpn --config internal.ovpn`

## Working with web services 

cURL allows transfer files from the shell over HTTP, HTTPS, FTP, SFTP, FTPS, or SCP

`curl <url>`

wget = alterternative to cURL; download files from FTP or HTTP servers from terminal 

will store the content downloaded locally instead of output

`wget <url>`

python 3 is another option for data transfer

`python3 -m http.server`

## Backup and Restore 

backing up an ubuntu system: 
- Rsync
- Deja Dup
- Duplicity

rsync = quick and secure back up files and folders to remote location  
transferring large data over network because it only transmits changed parts of a file  

duplicity = graphical backup tool that gives comprehensive data protection and secure backups  
uses rsync as backend and offers to encrypt backup copies and store them on remote media like FTP servers, cloud storage devices like S3

deja dup = graphical backup tool that simplifies backup, also uses rsync as backend 

important to encrypt backups with: 
- GnuPG
- eCryptfs
- LUKS

### Rsync 

backup local directory to backup server:

`rsync -av /path/to/local user@backup_server:/path/to/backup`

`-a` = preserve original file attributes (permissions, timestamps, etc.)
`-v` = verbose 

`rsync -avz --backup --backup-dir=/path/to/backup/folder --delete /path/to/mydir user@backup_server:/path/to/backup`

`-z` = enable compression
`--backup` = incremental backups in backup folder
`--delete` = removes files from the remote host no longer present in source dir

restore local directory from backup: 

`rsync -av user@remote_host:/path/to/backup /path/to/dir`

encrypting rsync with ssh and other security measures it makes much more difficult for unauthorized access 

`rsync -avz -e ssh /path/to/dir user@backup_server:/path/to/backup`

this will make it so the data transfer between our local dir and the backup dir will be encrypted over ssh

### Auto synchronization

can use cron to schedule syncs between the two systems at regular intervals

first create a new script RSYNC_Backup.sh: 

```
#!/bin/bash
rsync -avz -e ssh /path/to/dir user@backup_server:/path/to/backup
```

make sure that the script has the correct permissions and ownership:

`chmod +x RSYNC_Backup.sh` 

then create a crontab that runs the script every hour at the 0th minute: 

`0 * * * * /path/to/RSYNC_Backup.sh`

## File System Management

complex process that involves organizing and maintaining data stored on a disk or other storage device 

linux supports many types of file systems

linux file system based on unix file system  
hierarchical composed of various components    
**inode table** = basis for the entire file system; table of info and metadata for each file and directory

files can be stored as regular files or directories 

regular files = stored in root directory  
directories = store collection of files  

symbolic links = references to other files or directories 

`ls -il`

`-i` = inode; 

### Disks and drives

managing physical storage like HDD, SSD, and removable storage

fdisk = main tool for disk management  
create, delete, and manage partitions on a drive  
also give info on partition  

each partition can be formatted with a specific file system

common partitioning tools: 
- fdisk
- gpart
- GParted

![](../Images/Pasted%20image%2020231129213927.png)

mounting = each logical partition or drive needs to be assigned to a specific directory on Linux  
attaching a drive to a dir, making it accessible to the file system hierarchy

`mount` to mount file systems  
`/etc/fstab` = define the default file systems that are mounted at boot time

![](../Images/Pasted%20image%2020231129215931.png)

swap mount point = partition or file used as swap space; crucial for system stability and performance  
when system runs out of ram it can move less frequently used data from ram to swap space

`mount` can be used to see all mounted file systems: 

![](../Images/Pasted%20image%2020231129220133.png)

can mount a USB drive with: 

`sudo mount /dev/sdb1 /mnt/usb`

then unmount: 

`sudo umount /mnt/usb`

unmounting can't be done without proper permissions and you cant unmount a file system that is in use by a running process

can use `lsof` to list the open files on the file system:

`lsof | grep username`

can also add an entry to `/etc/fstab` to auto unmount a file system on shut down with noauto:

`/dev/sdb1 /mnt/usb ext4 rw,noauto,user 0 0 `

### SWAP

swap space can be created either during installation of OS or by using `mkswap` and `swapon` 

`mkswap` = set up linux swap area on a device or in a file
`swapon` = activate a swap area

important that swap space has dedicated partition or file, and is encrypted

also used for hibernation = save state to disk and then power off instead of shut down

## Containerization

packaging and running apps in isolated environments: container, VM, serverless env 

container tech for linux: 
- Docker 
- Docker Compose 
- Linux Containers 

create, deploy, and manage apps 

also good for running multiple apps at once for scalability and portability

good to ensure apps are managed and deployed efficiently and securely 

### Dockers 

docker = open source platform for auto deployment of apps as self-contained units called containers

uses layered filesystems and resource isolation features

create, deploy, and manage apps 

script to install docker: 

```bash
#!/bin/bash

# Preparation
sudo apt update -y
sudo apt install ca-certificates curl gnupg lsb-release -y
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add user htb-student to the Docker group
sudo usermod -aG docker htb-student
echo '[!] You need to log out and log back in for the group changes to take effect.'

# Test Docker installation
docker run hello-world
```

docker engine and docker images are needed to run a container, can get these from docker hub 

docker hub = repos or libraries of docker images 

creating a docker image is done with a **dockerfile** = contains all instructions the docker engine needs to create the container 

docker containers can be used as file hosting server when transferring files to target systems  
therefore we need to make dockerfile based on ubuntu with Apache and SSH  
can then use scp to transfer files to docker image and apache lets you host files that target system can download 

example dockerfile:

```
# use latest ubuntu as base image
FROM ubuntu:22.04

# update package repo and install required packages  
RUN apt-get update && \  
	apt-get install -y \  
		apache2 \  
		openssh-server \  
		&& \  
	rm -rf  /var/lib/apt/lists/*

# Create new user called student
RUN useradd -m docker-user && \
	echo "docker-user:password" | chpasswd

# give the htb-student user full access to the apache and ssh services 
RUN chown -R docker-user:docker-user /var/www/html && \
	chown -R docker-user:docker-user /var/run/apache2 && \
	chown -R docker-user:docker-user /var/log/apache2 && \
	chown -R docker-user:docker-user /var/lock/apache2 && \
	usermod -aG sudo docker-user && \

# expose the required ports
EXPOSE 22 80

CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```

with the new dockerfile we need to convert it to an image with `build`

build will execute the steps from the dockerfile and store the image in the local docker engine 

`docker build -t FS_docker` 

`-t `= give container a tag 

after creation it can be executed through docker engine 

container = running process of an image

start the container: 

`docker run -p <host port>:<docker port> -d <docker container name>`

`docker run -p 8022:22 -p 8080:80 -d FS_docker`

map the host ports 8022 and 8080 to 22 and 80, then we can access the SSH and HTTP services inside the container using the specified host ports

### Docker management 

common docker management commands: 
- docker ps = list all running containers
- docker stop = stop container
- docker start = start stopped container
- docker restart = restart running container 
- docker rm = remove a container
- docker rmi = remove a docker image
- docker logs = view the logs of the container

any changes made to existing image are not permanent, need to create new image that inherits from the original and includes the desired changes 

done by creating a new dockerfile that starts with `FROM` statement that specifies the base image, then adds necessary commands to add necessary changes 

containers are immutable - any changes made during runtime are lost when the container is stopped 

container orchestration tools: 
- Docker Compose 
- Kubernetes   
manage and scale containers in a production env

### Linux containers

linux containers = LXC = virtualization tech that allows multiple isolated linux systems to run on a single host 

resource isolation features such as cgroups and namespaces to provide lightweight virtualization solution

tools and APIs to manage and configure containers 

differences between LXC and docker: 
- approach
- image building
- portability 
- ease of use 
- security

lxc = virtualization tech that uses resource isolation features of linux kernel to provide isolated env 

built by creating a root filesystem and installing the required packages and configurations 

lxc containers are tied to host system and may not be easily portable 

security features may not be as robust as docker 

docker is application centric platform that builds on lxc

dockerfiles are portable 

installing lxc:

`sudo apt-get install lxc lxc-utils -y`

create an lxc container: 

`sudo lxc-create -n linuxcontainer -t ubuntu`

management commands:
- `lxc-ls` = list all containers
- `lxc-stop -n <container>` = stop a running container
- `lxc-start -n <container>` = start a stopped container
- `lxc-restart -n <container>` = restart a running container 
- `lxc-config -n <container> -s storage` = manage container storage
- `lxc-config -n <container> -s network` = manage container network settings
- `lxc-config -n <container> -s security` = manage container security settings
- `lxc-attach -n <container>` = connect to a container
- `lxc-attach -n <container> -f /path/to/share` = connect container and share a specific directory or file

linux containers help when we need to test app or systems with dependencies or configs that are hard to reproduce on our machines

standalone executable package containing all dependencies and configs needed to run a specific software or system

can quickly use containers to create isolated env specific to testing needs

can also use to test exploits or malware in a controlled environment 

security measures: 
- restricting access to the container
- limiting resources 
- isolating the container from the host 
- enforcing mandatory access control
- keeping the container up to date 

lxc containers can be accessed using SSH, console, etc. 

need to disable unnecessary services, use secure protocols, and enforce strong authentication mechanisms 

can use **cgroups** to limit the amount of CPU, memory, or disk space that a container can use because the container still uses the same kernel as the host machine

### Securing LXC 

can create a new config file in `/usr/share/lxc/config/<container>.conf` 

`sudo vim /usr/share/lxc/config/linuxcontainer.conf`

then add the lines: 

```
lxc.cgroup.cpu.shares = 512
lxc.cgroup.memory.limit_in_bytes = 512m
```

.shares = determines CPU time a container can use in relation to other containers on the system  
default = 1024

.limit_in_bytes = set max amount of memory a container can use 

need to restart to apply changes: 

`sudo systemctl restart lxc.service`

lxc use **namespaces** to provide isolated env 

namespaces = feature of linux kernel that allows for creating isolated env by abstracting system resources

each container given unique PID number space isolated from hosts PIDs  
also has its own network interfaces, routing tables, firewall rules  
any network-related activity withing container is cordoned off from the host system's network 

containers come with own root file system (mnt) 

important to remember that containers don't provide complete security 

## Network Configuration

network config tasks: 
- config network interfaces
- assigning IP addresses 
- config network devices such as routers and switches 
- setting up network protocols 

NAC:
- DAC
- MAC
- RBAC

need to understand NAC enforcement techniques and how to configure linux network devices for NAC 

SELinux policies, AppArmor profiles, and using TCP wrappers to control access 

network monitoring tools: 
- syslog
- rsyslog
- ss
- lsof
- ELK stack

### Configuring Network Interfaces 

configure local network interfaces with ifconfig and ip 

ifconfig deprecated for newer ip command 

`ip addr` similar to basic `ifconfig` command: 

![](../Images/Pasted%20image%2020231205141032.png)

setting up a network interface: 

![](../Images/Pasted%20image%2020231205141116.png)

can add an ip address to a network interface with: 

`sudo ifconfig eth0 192.19.1.0`

can also assign a netmask: 

![](../Images/Pasted%20image%2020231205141426.png)
![](../Images/Pasted%20image%2020231205141447.png)

default gateway = IP address of the router that will be used to send traffic to destinations outside local network 

can add default gateway with route add: 

`sudo route add default gw 192.168.1.1 eth0`

need to configure DNS servers so that devices can communicate with other devices and access websites/online resources 

`/etc/resolv.conf` = use to update DNS server configuration; file with system's DNS info 

edits to this file do not persist across reboots, so need to ensure that they do with `/etc/network/interfaces`:

![](../Images/Pasted%20image%2020231205150520.png)

need to then restart networking service to ensure changes are applied:

![](../Images/Pasted%20image%2020231205150648.png)



