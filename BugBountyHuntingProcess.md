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

