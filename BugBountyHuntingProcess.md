# Bug Bounty Hunting Process

## Bug Bounty Programs 

bug bounty programs can be seen as crowdsourcing initiatives that people can get recognition and compensation for discovering and reporting software bugs   
but they are more than that as they are continuous and proactive security testing that supplements internal code audits and penetration tests, and completes and orgs vulnerability management strategy   
hackerone describes their platform as continuous testing and constant protection 

### Bug bounty program types 

programs can be private or public 

private bug bounty programs are only open by invitation  
most programs start out as private until the company gets used to receiving and triaging vulnerability reports    
hackers will get invitations based on their track record, valid finding consistency, and violation record 

public programs are open to the entire hacking community 

parent/child programs also exist where a bounty pool and a single cyber security team are shared between a parent company and its subsidiaries   
if a subsidiary launches a bug bounty program (child) then this will be linked to the parent program 

bug bounty program (BBP) and vulnerability disclosure program (VDP) are not the same  
a VDP only provides guidance on how an org prefers receiving information on identified vulnerabilities by third parties   
a BBP incentivizes third parties to find bugs to then get monetary rewards 

### Bug bounty program code of conduct 

need to spend a lot of time reading the code of conduct that is for expectations of behavior and to make hunters more effective 

https://www.hacker101.com/resources/articles/code_of_conduct

### Bug bounty program structure 

https://hackerone.com/alibaba?type=team  
https://hackerone.com/amazonvrp?type=team

the policy section lets orgs publish info about their program to communicate specifics about the program to hackers   
orgs typically publish a vulnerability disclosure policy with guidance on how they want to get info related to potential vulnerabilities   
this policy also includes the scope which is what hackers can test and send reports for   

a bug bounty program usually has these elements: 
- `vendor response SLAs` - define when and how the vendor will reply
- `access` - how to create or obtain accounts for research purposes 
- `eligibility criteria` - eligible for compensation; ex: be the first to report a vulnerability 
- `response disclosure policy` - defines disclosure timelines, coordination actions to safely disclose a vulnerability, increase user safety, etc. 
- `rules of engagement` 
- `scope` - in-scope IP ranges, domains, vulnerabilities, etc. 
- `out of scope`
- `reporting format`
- `rewards` 
- `safe harbor` 
- `legal terms and conditions` 
- `contact info`

### Finding bug bounty programs

https://hackerone.com/directory/programs

the directory can be used to find orgs that have programs and contact info to report vulnerabilities you have ethically found 

## Writing a Good Report 

bug reports should be clear and concise while including info on how exploitation of each vulnerability can be reproduced step-by-step 

when reporting to less mature companies we might have to translate technical security issues into more understandable/business terms for them to understand the actual impact of each vulnerability 

the essential elements of a good report are: 
- `vulnerability title` - includes vulnerability type, affected domain/parameter/endpoint, impact, etc.
- `CWE & CVSS score` - communicates the characteristics and severity of the vulnerability 
- `vulnerability description` - better understanding of the vulnerability cause
- `proof of concept (POC)` - steps to reproduce 
- `impact` - elaborate more on what an attacker can achieve by fully exploiting the vulnerability; include business impact and maximum damage 
- `remediation` - optional but good to have 

### Why CWE & CVSS

MITRE describes common weaknesses enumeration (CWE) as a community developed list of software and hardware weakness types   
serves as a common language and as a baseline for weakness identification, mitigation, and prevention efforts   
in the case of a vulnerability chain, use the CWE used for the initial vulnerability 

the common vulnerability scoring system (CVSS) should be used to communicating the severity of an identified vulnerability  

### Using CVSS calculator 

https://www.first.org/cvss/calculator/3.1

we will focus on the base score area only: 

![](Images/Pasted%20image%2020240315115609.png)

#### Attack vector 

how the vulnerability can be exploited: 
- `Network (N)` - can only exploit through the network layer (remotely exploitable) 
- `Adjacent (A)` - can only exploit if they reside in the same physical or logical network (secure VPN included)
- `Local (L)` - only by accessing the target system locally (keyboard, terminal, etc.) or remotely (SSH) or through user interaction 
- `Physical (P)` - can exploit through physical interaction/manipulation 

#### Attack complexity 

depicts conditions outside the attacker's control and must be present to exploit the vulnerability repeatedly without any issue 

- `Low (L)` - no special preparations should take place to exploit the vulnerability successfully; attackers can exploit the vulnerability repeatedly without any issue 
- `High (H)` - special preparations and info gathering should take place to exploit the vulnerability successfully 

#### Privileges required 

the level of privileges the attacker must have to exploit the vulnerability successfully 

- `None (N)` - no special access related to settings or files is required to exploit the vulnerability successfully; can be exploited from unauthorized perspective 
- `Low (L)` - attackers should possess standard user privileges to exploit the vulnerability; usually affects files and settings owned by a user or non-sensitive assets 
- `High (H)` - should possess admin-level privileges to exploit the vulnerability successfully; exploitation usually affects the entire vulnerable system 

#### User interaction 

if attackers can exploit the vulnerability on their own or with user interaction  

- `None (N)` - can exploit independently 
- `Required (R)` - take some action before the attackers can successfully exploit the vulnerability 

#### Scope 

shows if successful exploitation can affect other components than the one targeted 

- `Unchanged (U)` - only affects the vulnerable component or affects resources managed by the same security authority 
- `Changed (C)` - can affect other components or resources beyond the scope of the affected components security authority 

#### Confidentiality 

how much the vulnerable component's confidentiality is affected upon successfully exploiting the vulnerability   
confidentiality limits info access and disclosure to authorized users only and prevents unauthorized users from accessing info 

- `None (N)` - confidentiality of vulnerable component does not get impacted 
- `Low (L)` - will experience some loss of confidentiality; attackers do not have control over what info is obtained 
- `High (H)` - total or serious loss of confidentiality; attackers have total or some control over what info is obtained 

#### Integrity 

how much the vulnerable component's integrity is affected   
integrity is the trustworthiness of the info 

- `None (N)` - integrity does not get impacted 
- `Low (L)` - can modify data in a limited manner on the vulnerable component; attackers do not have control over the consequence of a modification, and vulnerable component does not get seriously affected in this case 
- `High (H)` - attackers can modify all or critical data on the vulnerable component and do have control over the consequence of a modification; vulnerable component will suffer total loss of integrity 

#### Availability 

how much the availability is affected   
availability is the accessibility of info resources in terms of network bandwidth, disk space, processor cycles, etc. 

- `None (N)` - does not get impacted 
- `Low (L)` - experience some loss of availability; attacker does not have complete control over the vulnerable component's availability and cannot deny the service to users, but performance is reduced 
- `High (H)` - vulnerable component will experience total or severe availability loss; attacker has complete or significant control over the vulnerable component's availability and can deny the service to users, performance is significantly reduced 

### Examples 

![](Images/Pasted%20image%2020240315131156.png)

![](Images/Pasted%20image%2020240315131206.png)

### Good report examples

- [SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876)
- [Remote Code Execution in Slack desktop apps + bonus](https://hackerone.com/reports/783877)
- [Full name of other accounts exposed through NR API Explorer (another workaround of #476958)](https://hackerone.com/reports/520518)
- [A staff member with no permissions can edit Store Customer Email](https://hackerone.com/reports/980511)
- [XSS while logging in using Google](https://hackerone.com/reports/691611)
- [Cross-site Scripting (XSS) on HackerOne careers page](https://hackerone.com/reports/474656)

## Interacting with Organizations/BBP Hosts

after submitting a bug report, how should you interact with the security/triage team after that? 

first allow them time to process your report, validate your finding, and maybe ask questions   
some programs include vendor response SLAs or response efficiency metrics which give you an idea of how long it will take to get a response 

you could also contact mediation: https://docs.hackerone.com/en/articles/8466617-hacker-mediation if the org is not responding in a timely manner

once the team gets back to you, take note of the team member's username and tag them in future communications since they will likely continue to deal with the submission   
do not interact outside any unofficial communication channel 

during your interaction with the security team there could be disagreements about the severity of the bug or bounty, which may impact the reward from the bounty      
in the case, proceed as follows: 
- explain your rationale for choosing this severity score and guide the team through each metric value you used in the calculator 
- go over the bug bounty programs policy and scope and make sure your submission complies with both, and make sure the bounty amount resembles the policy of the program 
- if none of the above works then contact mediation 

## Example 1: Reporting Stored XSS 

**Note**: Real reports should not used shortened language or brief summaries as the below examples will use

Title - stored XSS in X admin panel 

CWE - https://cwe.mitre.org/data/definitions/79.html

CVSS 3.1 Score - 5.5. (Medium) 

Description - found that the web app was vulnerable to stored cross site scripting attacks due to inadequate sanitation. The file uploading mechanism utilizes user input unsanitized which is reflected back to the user's browser and stored in the web app database. This results in the app being vulnerable to XSS because JS code can be entered in the filename field 

Impact - cross site scripting issues occur when an app uses untrusted input data without sufficient prior validation or escaping. Attackers can use XSS to execute scripts in a legitimate user's browser leading to user credentials theft, session hijacking, site defacement, or redirection to malicious sites. Anyone that can send data to the system, including admins are possible candidates for performing XSS attacks against. 

POC: 

Step 1: A malicious admin could leverage the fact that the filename is reflected back to perform XSS attacks against other admins. This is feasible because admins can view all uploaded files regardless of the uploader. For example: 

![](Images/Pasted%20image%2020240315140027.png)

![](Images/Pasted%20image%2020240315140038.png)

Step 2: When another admin clicks the view button to the uploaded file the JS code will execute on the browser: 

![](Images/Pasted%20image%2020240315140117.png)

### CVSS score breakdown 

![](Images/Pasted%20image%2020240315140203.png)

## Example 2: Reporting CSRF 

Title - CSRF in consumer registration 

CWE - https://cwe.mitre.org/data/definitions/352.html

CVSS 3.1 Score - 5.4 (Medium)

Description - We have identified a we page responsible for consumer registration that is vulnerable to CSRF attacks. CSRF is an attack where the attacker tricks the victim into loading a page that contains a malicious request. It will use the identity and privileges of the authenticated victim to perform undesired actions like changing their email address, home address, password, etc. CSRF attacks generally target functions that cause a state change on the server but can also be used to access sensitive data. 

Impact - impact of CSRF depends on the nature of the vulnerable functionality. Attacker could effectively perform any operations as the victim. CSRF limited only by the permissions of the victim. 

POC: 

Step 1: Using a proxy we captured a request to create a new fintech app, and there were no anti-CSRF tokens in place

![](Images/Pasted%20image%2020240316174256.png)

Step 2: We then use the request to craft a malicious HTML page that when visited by an authenticated victim with a valid session will result in an advertent creation of an attacker-specific fintech app. 

![](Images/Pasted%20image%2020240316174359.png)

Step 3: To complete the attack we send our malicious web page to the victim 

Step 4: The result would be the inadvertent creation of a new app by the victim. Important to note that this attack could have taken place in the background if combined with the finding 6.1.1 <-- 6.1.1 was an XSS vulnerability 

![](Images/Pasted%20image%2020240316174549.png)

### CVSS score breakdown 

![](Images/Pasted%20image%2020240316174607.png)

## Example 3: Reporting RCE 

Title - IBM websphere java object deserialization RCE 

CWE - https://cwe.mitre.org/data/definitions/502.html

CVSS 3.1 Score - 9.8 (Critical)

Description - We have identified that the remote websphere app server contains a vulnerability related to insecure java object deserialization allowing remote attackers to execute arbitrary commands. By issuing a request to the remote websphere server over HTTPS on port 8880 we identified the existence of raw, serialized java objects that were base64-encoded. It is possible to identify these objects by the "rO0" header. We were able to craft a SOAP request containing a serialized Java object that can exploit the vulnerability in the Apache Commons Collections (ACC) library used by the websphere app server. The crafted object contains the `ping` command to be executed by the affected system. 

Impact - Command injection vulnerabilities typically occur when data enters the app from an untrusted source like a terminal or a network socket, without authenticating the source, or the data is in a string that is executed as a command by the application. Without validating the input against a predefined list of allowed commands like a whitelist thne the app executed the provided command. If the app is executed as a privileged user then it can potentially allow a complete takeover of the affected system. 

POC: 

Step 1: We identified that the app was using serialized data objects by capturing and decoding a request to port 8880 of the server. 

![](Images/Pasted%20image%2020240316181207.png)

Step 2: We then crafted a SOAP request containing a command to be executed by the remote server. The command would send ping messages from the affected server to our host

![](Images/Pasted%20image%2020240316181301.png)

Step 3: Using wireshark we can observe the resulting ping requests

![](Images/Pasted%20image%2020240316181337.png)

### CVSS score breakdown 

![](Images/Pasted%20image%2020240316181359.png)

