## DLL Side-Loading or Hijacking

**Summary:**

DLL Side-Loading or Hijacking refers to the execution of attacker-controlled dynamic libraries through the misuse of legitimate application loading behavior. This includes placing malicious libraries in directories searched by trusted programs so that the operating system loads attacker-provided code instead of legitimate components. Within MalChain, this capability begins once a trusted application loads a manipulated or substituted library during execution. Attackers exploit implicit trust in application dependencies and library search order mechanisms to execute code without triggering traditional security controls. Operational reliance on shared libraries and automated loading behavior often allows malicious modules to execute silently. Trust abuse may involve renamed library files, copied application directories, or manipulated software packages presented as legitimate installations. Common execution methods include:

* Placing malicious libraries in application directories  
* Replacing legitimate dependency files with modified versions  
* Loading libraries through portable or relocated applications  
* Executing programs that automatically search local directories for libraries  
* Delivering applications bundled with malicious dependency files  

Real world usage includes:

* Advanced persistent threat operations targeting enterprise software  
* Software supply chain and update manipulation campaigns  
* Stealthy malware deployment within trusted applications  
* Evasion of application whitelisting and security monitoring controls  

**Detection:**

Detection relies on monitoring module load events, application behavior, and file integrity changes associated with library dependencies. Contextual correlation between application execution and unexpected library loading activity is essential to reduce false positives.

* Monitor library load events from non-standard directories  
* Detect execution of applications loading unsigned or unknown modules  
* Correlate application launches with recent file creation events  
* Alert on duplicate library names located in unexpected paths  
* Identify applications executing from temporary or user-controlled locations  

**KQL Detection Concepts:**

* Module load events referencing libraries outside trusted system directories  
* Application processes loading unsigned or newly created DLL files  
* Execution of portable applications from user-writable locations  

**YARA Detection Concepts:**

* Suspicious library export tables or abnormal function mappings  
* Libraries containing embedded shellcode or execution routines  
* Files masquerading as legitimate dependency modules  

**Mitigation:**

* Enforce application and library integrity validation  
* Restrict execution from untrusted directories  
* Implement code signing and dependency verification controls  
* Monitor application installation and update processes  

**Incident response:**

* Identify the application responsible for loading the malicious library  
* Isolate affected systems from the network  
* Collect and analyze suspicious library files  
* Review execution timelines and dependency changes  

**Linking:**

* WMI-Based Execution  
* Registry-Based Persistence  
* Process Injection
