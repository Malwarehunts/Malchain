## Script-Based Execution

**Summary:**

Script-Based Execution refers to the use of scripting engines or interpreters to run attacker-controlled logic within a target environment. This includes command shells, automation frameworks, and scripting runtimes capable of executing instructions without requiring compiled binaries. Within MalChain, this capability begins once a script is invoked or interpreted by a trusted runtime component. Attackers exploit implicit trust in administrative tools and automation workflows to perform actions while minimizing visible artifacts. Convenience, automation requirements, and administrative flexibility often allow script execution without strict validation. Trust abuse may involve encoded commands, hidden scripts, or automation routines presented as maintenance or operational tasks. Common execution methods include:

* Command-line script invocation  
* PowerShell or shell interpreter execution  
* Script execution from temporary directories  
* Automated task or login script execution  
* Encoded or obfuscated command execution  

Real world usage includes:

* Fileless malware deployment campaigns  
* Remote administration abuse in enterprise environments  
* Ransomware staging and system reconnaissance  
* Living-off-the-land operational techniques  

**Detection:**

Detection relies on monitoring interpreter activity, command-line parameters, and runtime behavior associated with scripting engines. Contextual correlation between script origin, execution context, and system changes is essential to reduce false positives.

* Monitor execution of scripting interpreters and shells  
* Detect encoded or obfuscated command-line arguments  
* Correlate script execution with privilege changes  
* Alert on scripts launched from user-writable directories  
* Identify rare or high-risk command sequences  

**KQL Detection Concepts:**

* Script interpreter process creation events  
* Execution of commands containing encoded or compressed content  
* Script execution originating from temporary or download paths  

**YARA Detection Concepts:**

* Suspicious script command patterns or encoded payload indicators  
* Script files containing embedded system manipulation logic  
* Scripts invoking administrative or network control functions  

**Mitigation:**

* Restrict scripting engine usage to authorized roles  
* Enforce script execution policies and signing requirements  
* Monitor and limit execution from untrusted locations  
* Educate administrators on secure scripting practices  

**Incident response:**

* Identify executed scripts and associated processes  
* Capture command-line history and execution context  
* Analyze script content and runtime behavior  
* Review system changes performed by executed scripts  

**Linking:**

* Service-Based Execution  
* DLL Side-Loading  
* Scheduled & Triggered Execution
