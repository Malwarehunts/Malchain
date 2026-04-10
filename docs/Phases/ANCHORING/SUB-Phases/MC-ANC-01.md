## Startup & Logon Execution

**Summary:**

Startup & Logon Execution refers to the automatic execution of attacker-controlled logic when a system starts or a user logs into an environment. This includes configuring programs, scripts, or system components to run during initialization sequences without requiring manual interaction. Within MalChain, this capability begins once execution is reliably triggered by system startup or user authentication events. Attackers exploit implicit trust in routine initialization processes and user session management to maintain consistent execution across system restarts. Operational requirements and automated system behavior often allow startup mechanisms to run without continuous verification. Trust abuse may involve modified startup folders, login scripts, or configuration settings presented as legitimate system components. Common execution methods include:

* Placing executable files in startup directories  
* Modifying login or initialization scripts  
* Configuring applications to run automatically at user logon  
* Altering system startup configuration settings  
* Registering programs to execute during system boot or session start  

Real world usage includes:

* Persistence mechanisms in enterprise malware campaigns  
* Automated execution of surveillance or monitoring tools  
* Ransomware deployment triggered after system restart  
* Long-term system access in targeted intrusion operations  

**Detection:**

Detection relies on monitoring system initialization behavior, configuration changes, and execution patterns associated with startup or logon events. Contextual correlation between configuration changes and repeated execution activity is essential to reduce false positives.

* Monitor creation or modification of startup configuration entries  
* Detect execution of programs immediately after system startup  
* Correlate login activity with unexpected application launches  
* Alert on changes to initialization scripts or configuration files  
* Identify rare or unauthorized programs executing at session start  

**KQL Detection Concepts:**

* Process execution events occurring immediately after system boot or user logon  
* Configuration changes to startup directories or initialization settings  
* Repeated execution of programs triggered by authentication events  

**YARA Detection Concepts:**

* Files designed to execute automatically during startup sequences  
* Scripts containing initialization or session-triggered logic  
* Executable components referencing startup configuration paths  

**Mitigation:**

* Restrict modification of startup configuration settings  
* Enforce application control for automatically executed programs  
* Monitor system initialization behavior and configuration changes  
* Implement user session management and access control policies  

**Incident response:**

* Identify startup or logon configuration changes  
* Disable unauthorized automatic execution mechanisms  
* Analyze executed programs and associated configuration files  
* Review authentication and system startup timelines  

**Linking:**

* Scheduled & Triggered Execution  
* Registry-Based Persistence  
* Log & Artifact Manipulation
