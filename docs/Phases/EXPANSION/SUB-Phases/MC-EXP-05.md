## Network Share Propagation

**Summary:**

Network Share Propagation refers to the distribution of attacker-controlled files or execution logic across systems through shared storage resources within a target environment. This includes copying malicious files to shared folders, mapped drives, or collaborative storage locations accessible by multiple users or systems. Within MalChain, this capability begins once attacker-controlled content is successfully placed on a shared resource and becomes accessible for execution on additional systems. Attackers exploit implicit trust in shared storage infrastructure and collaborative workflows to expand operational reach while minimizing direct interaction with each target system. Routine reliance on network file sharing and centralized storage often allows unauthorized file distribution to occur without immediate detection. Trust abuse may involve placing disguised executables in shared directories, modifying shared scripts, or distributing files presented as legitimate updates or operational tools. Common propagation methods include:

* Copying malicious files to shared network folders  
* Placing executable content on mapped drives  
* Modifying shared scripts or configuration files  
* Using shared storage to distribute payloads across systems  
* Leveraging automated synchronization to replicate files  

Real world usage includes:

* Ransomware campaigns spreading payloads through shared drives  
* Enterprise intrusion operations distributing tools across departments  
* Insider threat scenarios involving unauthorized file placement  
* Persistent threats expanding access through shared infrastructure  

**Detection:**

Detection relies on monitoring file transfer activity, shared resource usage, and execution patterns associated with distributed content. Contextual correlation between file placement and subsequent execution behavior is essential to reduce false positives.

* Monitor file creation events on shared storage resources  
* Detect large-scale file copying between network shares  
* Correlate file access with execution attempts on multiple systems  
* Alert on executable files placed in shared directories  
* Identify rare or unauthorized modifications to shared files  

**KQL Detection Concepts:**

* File creation or modification events occurring on network shares  
* Execution of files originating from shared storage locations  
* Repeated file distribution activity across multiple systems  

**YARA Detection Concepts:**

* Executable files designed for propagation across shared environments  
* Scripts containing automated file distribution logic  
* Code patterns interacting with network file sharing mechanisms  

**Mitigation:**

* Restrict write access to shared directories based on role  
* Implement file integrity monitoring on shared storage  
* Monitor shared resource activity and access permissions  
* Enforce application control for executable files on shared drives  

**Incident response:**

* Identify shared locations containing unauthorized files  
* Remove malicious content from network shares  
* Review access logs for file distribution activity  
* Analyze execution history associated with shared resources  

**Linking:**

* Worm-like Self-Propagation  
* Privilege Escalation Across Hosts  
* FTP / SFTP / FTPS Transfer
