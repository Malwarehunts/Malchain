## HTTP / HTTPS Data Exfiltration

**Summary:**

HTTP / HTTPS Data Exfiltration refers to the transfer of attacker-controlled data from a target environment to external systems using standard web communication protocols. This includes sending files, credentials, or system information through web requests that appear consistent with routine internet activity. Within MalChain, this capability begins once sensitive data is transmitted beyond the environment using trusted web communication channels. Attackers exploit implicit trust in web traffic and encrypted communication to move data without triggering traditional network restrictions. Routine reliance on web services and secure connections often allows outbound communication to occur without deep inspection. Trust abuse may involve sending data to remote servers, embedding information in web requests, or using encrypted sessions presented as legitimate application traffic. Common exfiltration methods include:

* Uploading files to external web servers  
* Transmitting data through web application requests  
* Sending encoded information in HTTP or HTTPS traffic  
* Using web APIs to transfer sensitive content  
* Leveraging encrypted connections to conceal data movement  

Real world usage includes:

* Data theft operations targeting enterprise databases  
* Ransomware campaigns transferring stolen information before encryption  
* Insider threat scenarios involving unauthorized file uploads  
* Persistent threats maintaining covert communication channels  

**Detection:**

Detection relies on monitoring outbound web traffic, data transfer patterns, and communication behavior associated with external connections. Contextual correlation between network activity and data access is essential to reduce false positives.

* Monitor large or unusual outbound data transfers over web protocols  
* Detect communication with unfamiliar external domains  
* Correlate data access activity with outbound network connections  
* Alert on repeated uploads to external web services  
* Identify rare or unauthorized web communication patterns  

**KQL Detection Concepts:**

* Network events indicating outbound HTTP or HTTPS connections  
* Data transfer activity associated with external web services  
* Repeated communication with newly registered or unknown domains  

**YARA Detection Concepts:**

* Scripts or binaries initiating outbound web communication routines  
* Code patterns associated with data upload or transfer mechanisms  
* Executable components interacting with web APIs for data transmission  

**Mitigation:**

* Implement outbound traffic filtering and inspection policies  
* Monitor web communication behavior and data transfer activity  
* Restrict access to unauthorized external web services  
* Enforce data loss prevention and network monitoring controls  

**Incident response:**

* Identify systems initiating external web communication  
* Block connections to suspicious domains or endpoints  
* Analyze transferred data and associated system activity  
* Review network logs and communication timelines  

**Linking:**

* DNS Tunneling  
* Cloud Storage Abuse  
* Multi-Channel Redundant Exfiltration
