## FTP / SFTP / FTPS Transfer

**Summary:**

FTP / SFTP / FTPS Transfer refers to the use of file transfer protocols to move attacker-controlled data between a target environment and external systems. This includes uploading files to remote servers, downloading tools from external sources, or synchronizing data through automated transfer mechanisms. Within MalChain, this capability begins once data is transmitted through file transfer services outside the organizational boundary. Attackers exploit implicit trust in established file transfer infrastructure and routine data exchange workflows to move information while appearing consistent with legitimate operations. Routine reliance on automated file transfer processes and scheduled data synchronization often allows unauthorized transfers to occur without immediate detection. Trust abuse may involve connecting to unauthorized file transfer servers, using embedded credentials, or automating transfers presented as routine operational activity. Common transfer methods include:

* Uploading files to external FTP or SFTP servers  
* Downloading tools or scripts from remote file repositories  
* Automating file synchronization between systems  
* Transferring data through scheduled file transfer jobs  
* Using encrypted file transfer channels to conceal data movement  

Real world usage includes:

* Data exfiltration campaigns transferring sensitive files to remote servers  
* Ransomware operators staging payloads through file transfer infrastructure  
* Insider threat scenarios involving unauthorized data uploads  
* Persistent threats maintaining remote storage of stolen information  

**Detection:**

Detection relies on monitoring file transfer activity, connection behavior, and data movement patterns associated with file transfer protocols. Contextual correlation between file access and network activity is essential to reduce false positives.

* Monitor connections to external file transfer servers  
* Detect large or unusual file upload or download activity  
* Correlate file transfer events with sensitive data access  
* Alert on automated transfer jobs outside approved schedules  
* Identify rare or unauthorized file transfer connections  

**KQL Detection Concepts:**

* Network events indicating connections to FTP or SFTP servers  
* File transfer activity associated with external destinations  
* Authentication events involving file transfer accounts  

**YARA Detection Concepts:**

* Scripts or binaries implementing automated file transfer routines  
* Code patterns associated with FTP or SFTP communication  
* Executable components transferring files to remote servers  

**Mitigation:**

* Restrict access to external file transfer services  
* Monitor file transfer activity and enforce transfer policies  
* Implement data loss prevention controls for outbound transfers  
* Enforce strong authentication for file transfer accounts  

**Incident response:**

* Identify systems involved in unauthorized file transfer activity  
* Block connections to suspicious file transfer servers  
* Analyze transferred files and associated system behavior  
* Review transfer logs and communication timelines  

**Linking:**

* Tor / Proxy / VPN Anonymization Channels  
* Encrypted Command-and-Control Channels  
* Multi-Channel Redundant Exfiltration
