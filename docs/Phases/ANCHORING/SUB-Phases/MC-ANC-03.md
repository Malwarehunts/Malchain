## Service & Daemon Persistence

**Summary:**

Service & Daemon Persistence refers to the establishment of attacker-controlled execution through background services or daemons configured to run automatically within a target environment. This includes installing new services, modifying existing service definitions, or leveraging system service management mechanisms to maintain continuous execution. Within MalChain, this capability begins once a service or daemon is configured to start automatically and sustain execution across system restarts or configuration changes. Attackers exploit implicit trust in system service infrastructure and administrative tooling to maintain reliable presence with elevated privileges. System stability requirements and automated service management often allow background processes to operate with limited visibility. Trust abuse may involve service names resembling legitimate components, modified execution paths, or binaries presented as routine maintenance utilities. Common persistence methods include:

* Installing new services configured for automatic startup  
* Modifying existing service execution parameters  
* Registering background daemons to run continuously  
* Configuring services to restart automatically after termination  
* Deploying services designed to maintain persistent communication  

Real world usage includes:

* Long-term persistence mechanisms in enterprise compromise operations  
* Continuous execution of command-and-control communication services  
* Privileged persistence in ransomware and intrusion campaigns  
* Maintenance of surveillance or monitoring components in targeted attacks  

**Detection:**

Detection relies on monitoring service lifecycle events, configuration changes, and execution patterns associated with background service activity. Contextual correlation between service creation, modification, and repeated execution behavior is essential to reduce false positives.

* Monitor creation of new services or daemon processes  
* Detect changes to service startup configuration or execution paths  
* Correlate service activity with privileged account usage  
* Alert on services installed from temporary or user-controlled locations  
* Identify rare or unauthorized services configured for automatic execution  

**KQL Detection Concepts:**

* Service installation or modification events recorded in system logs  
* Service processes configured for automatic startup at system initialization  
* Execution of services originating from non-standard or user-writable directories  

**YARA Detection Concepts:**

* Service binaries containing persistence or remote communication logic  
* Configuration files defining automatic service execution behavior  
* Executable components designed to operate as background daemons  

**Mitigation:**

* Restrict permissions to create or modify system services  
* Enforce service configuration auditing and approval workflows  
* Monitor service startup behavior and configuration changes  
* Implement application control policies for service executables  

**Incident response:**

* Identify newly created or modified services or daemons  
* Disable or remove unauthorized service configurations  
* Analyze associated service binaries and execution behavior  
* Review system logs and service startup timelines  

**Linking:**

* Registry-Based Persistence  
* Log & Artifact Manipulation  
* Remote Service & Protocol Abuse
