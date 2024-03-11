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

