## Process Injection

**Summary:**

Process Injection refers to the insertion of attacker-controlled code into the memory space of a legitimate running process within a target environment. This includes modifying process memory, spawning remote threads, or manipulating execution flow to run malicious logic under the identity of a trusted application. Within MalChain, this capability begins once code is successfully introduced into another process and executed without creating a separate standalone process. Attackers exploit implicit trust in legitimate system processes and security assumptions about running applications to conceal malicious activity. Routine reliance on trusted processes and shared memory operations often allows injected code to execute with reduced visibility. Trust abuse may involve targeting high-privilege system processes, modifying execution contexts, or embedding hidden payloads presented as routine process activity. Common injection methods include:

* Writing malicious code into the memory of a running process  
* Creating remote threads to execute injected payloads  
* Modifying process execution flow or memory structures  
* Leveraging legitimate system utilities to perform injection  
* Using process hollowing or similar memory manipulation techniques  

Real world usage includes:

* Stealthy malware execution within trusted system processes  
* Privilege escalation and persistence in enterprise intrusion campaigns  
* Evasion of endpoint detection systems through hidden execution  
* Deployment of command-and-control logic inside legitimate applications  

**Detection:**

Detection relies on monitoring memory manipulation behavior, process relationships, and execution anomalies associated with injected code. Contextual correlation between process activity and unexpected memory operations is essential to reduce false positives.

* Monitor processes performing memory write operations to other processes  
* Detect creation of remote threads within legitimate applications  
* Correlate abnormal parent-child process relationships  
* Alert on unexpected execution originating from injected memory regions  
* Identify rare or unauthorized process behavior patterns  

**KQL Detection Concepts:**

* Process events indicating cross-process memory modification  
* Creation of threads in processes not normally associated with execution  
* Execution behavior inconsistent with normal process activity  

**YARA Detection Concepts:**

* Memory patterns associated with injected shellcode  
* Code structures indicating process hollowing or thread injection  
* Executable components designed to manipulate process memory  

**Mitigation:**

* Implement memory protection and application isolation controls  
* Monitor process behavior and inter-process communication  
* Restrict privileges required for memory manipulation operations  
* Deploy endpoint detection and response monitoring solutions  

**Incident response:**

* Identify processes involved in memory manipulation activity  
* Capture memory snapshots for forensic analysis  
* Terminate compromised processes and isolate affected systems  
* Review execution timelines and system activity  

**Linking:**

* Polymorphism & Metamorphism  
* Log & Artifact Manipulation  
* Privilege Escalation Across Hosts
