## Privilege Escalation Across Hosts

**Summary:**

Privilege Escalation Across Hosts refers to the process of gaining elevated permissions or administrative control on additional systems within a target environment after initial access has been established. This includes exploiting misconfigurations, weak access controls, or privilege inheritance mechanisms to obtain higher levels of authority across multiple hosts. Within MalChain, this capability begins once attacker-controlled activity successfully transitions from standard user privileges to administrative or system-level access on remote systems. Attackers exploit implicit trust in delegated permissions, shared administrative roles, and inherited access rights to expand control beyond initial boundaries. Routine reliance on centralized management and administrative privileges often allows escalation activity to occur without immediate scrutiny. Trust abuse may involve leveraging service accounts, exploiting configuration weaknesses, or inheriting elevated permissions presented as legitimate administrative access. Common escalation methods include:

* Exploiting misconfigured permissions on remote systems  
* Using administrative credentials to gain elevated access  
* Leveraging service accounts with excessive privileges  
* Inheriting permissions through group membership or role delegation  
* Executing privileged commands across multiple hosts  

Real world usage includes:

* Enterprise intrusion campaigns gaining administrative control across networks  
* Ransomware operators escalating privileges before widespread deployment  
* Insider threat scenarios abusing delegated administrative access  
* Persistent threats maintaining system-wide authority for long-term operations  

**Detection:**

Detection relies on monitoring privilege changes, role assignments, and administrative activity associated with elevated access. Contextual correlation between privilege escalation events and system behavior is essential to reduce false positives.

* Monitor creation or modification of privileged user accounts  
* Detect assignment of administrative roles to unexpected users  
* Correlate privilege changes with system configuration modifications  
* Alert on execution of privileged commands across multiple hosts  
* Identify rare or unauthorized elevation of permissions  

**KQL Detection Concepts:**

* Events indicating changes to user roles or administrative privileges  
* Execution of commands requiring elevated permissions  
* Authentication activity associated with privileged accounts  

**YARA Detection Concepts:**

* Scripts or binaries designed to modify permission settings  
* Code patterns associated with privilege escalation routines  
* Executable components interacting with system authorization mechanisms  

**Mitigation:**

* Enforce least-privilege access control policies  
* Monitor role assignments and privilege usage continuously  
* Implement multi-factor authentication for administrative accounts  
* Conduct regular audits of permission configurations  

**Incident response:**

* Identify accounts granted elevated privileges  
* Revoke unauthorized permissions immediately  
* Review system logs for escalation activity  
* Assess impact on affected systems and services  

**Linking:**

* Identity & Trust Relationship Abuse  
* Directory Services Targeting  
* Encrypted Command-and-Control Channels
