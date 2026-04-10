## Registry-Based Persistence

**Summary:**

Registry-Based Persistence refers to the use of system configuration settings within the operating system registry to maintain attacker-controlled execution across system restarts or user sessions. This includes creating, modifying, or leveraging registry keys that automatically launch programs, scripts, or services during system initialization or user authentication. Within MalChain, this capability begins once registry entries are configured to reliably trigger execution without requiring repeated attacker interaction. Attackers exploit implicit trust in system configuration mechanisms and automated startup behavior to sustain long-term presence. System configuration flexibility and routine administrative changes often allow registry modifications to occur without immediate detection. Trust abuse may involve hidden registry keys, modified execution paths, or configuration entries presented as legitimate system settings. Common persistence methods include:

* Creating registry keys that trigger execution at system startup  
* Modifying existing registry entries to launch malicious programs  
* Configuring autorun or run-once registry settings  
* Registering scripts or executables as system initialization components  
* Using registry entries to redirect execution paths  

Real world usage includes:

* Persistence mechanisms in enterprise intrusion campaigns  
* Automated execution of malware following system reboot  
* Long-term access maintenance in targeted espionage operations  
* Configuration-based persistence in ransomware and surveillance tools  

**Detection:**

Detection relies on monitoring registry modification events, configuration changes, and execution behavior associated with system startup entries. Contextual correlation between registry changes and subsequent process execution is essential to reduce false positives.

* Monitor creation or modification of registry startup keys  
* Detect changes to execution paths defined in registry settings  
* Correlate registry activity with process launches after reboot  
* Alert on registry entries referencing user-controlled directories  
* Identify rare or unauthorized registry configuration changes  

**KQL Detection Concepts:**

* Registry modification events associated with startup or initialization keys  
* Process execution triggered by recently modified registry entries  
* Registry entries referencing executable files in temporary directories  

**YARA Detection Concepts:**

* Registry configuration patterns associated with persistence mechanisms  
* Scripts or binaries referencing registry autorun keys  
* Executable components designed to modify registry settings  

**Mitigation:**

* Restrict permissions to modify critical registry keys  
* Enforce registry change auditing and monitoring policies  
* Monitor startup configuration and execution behavior  
* Implement configuration integrity validation controls  

**Incident response:**

* Identify newly created or modified registry entries  
* Remove unauthorized registry persistence mechanisms  
* Analyze associated executables or scripts  
* Review system startup and configuration timelines  

**Linking:**

* Browser-Based Persistence  
* Log & Artifact Manipulation  
* Privilege Escalation Across Hosts
