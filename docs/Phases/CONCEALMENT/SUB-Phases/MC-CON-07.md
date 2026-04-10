## Polymorphism & Metamorphism

**Summary:**

Polymorphism & Metamorphism refers to the continuous modification of attacker-controlled code to evade detection mechanisms within a target environment. This includes dynamically changing code structure, encryption keys, or instruction sequences while preserving the original functionality of the malicious logic. Within MalChain, this capability begins once code is automatically altered to produce new variants that avoid signature-based detection or analysis. Attackers exploit implicit trust in static detection mechanisms and predictable pattern recognition systems to maintain stealth and operational persistence. Routine reliance on known signatures and consistent file structures often allows modified code to bypass defensive controls. Trust abuse may involve encrypted payloads, randomized execution routines, or self-modifying code presented as normal software behavior. Common evasion methods include:

* Automatically generating new variants of executable code  
* Encrypting payloads with changing keys  
* Rewriting instruction sequences during execution  
* Modifying file structure while preserving functionality  
* Using self-modifying or dynamically generated code  

Real world usage includes:

* Malware families designed to evade signature-based detection systems  
* Ransomware campaigns using continuously changing payload variants  
* Persistent threats adapting code to bypass updated security controls  
* Automated malware distribution systems generating unique samples  

**Detection:**

Detection relies on monitoring behavioral consistency, code transformation patterns, and execution anomalies associated with dynamically changing software. Contextual correlation between repeated activity and variable code signatures is essential to reduce false positives.

* Monitor files that repeatedly change structure without functional changes  
* Detect execution behavior consistent across multiple unique file hashes  
* Correlate file creation events with rapidly changing binary characteristics  
* Alert on processes generating new executable variants  
* Identify rare or unusual patterns of code transformation  

**KQL Detection Concepts:**

* Multiple executable files created with similar behavior but different hashes  
* Repeated process execution associated with dynamically generated files  
* File modification events indicating frequent structural changes  

**YARA Detection Concepts:**

* Code patterns associated with self-modifying logic  
* Executables containing dynamic encryption or decryption routines  
* File structures designed to change during execution  

**Mitigation:**

* Implement behavior-based detection and anomaly monitoring  
* Use reputation and integrity validation systems  
* Monitor repeated file generation or transformation activity  
* Maintain updated detection rules for evolving threats  

**Incident response:**

* Identify processes generating modified code variants  
* Collect and analyze multiple file samples for comparison  
* Isolate affected systems to prevent propagation  
* Review execution timelines and transformation patterns  

**Linking:**

* Log & Artifact Manipulation  
* Anti-Forensics & Cleanup  
* Multi-Channel Redundant Exfiltration
