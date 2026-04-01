# Malchain Phases

## **[MC-ING](/INGRESS.md)** Ingress - Initial Access Capability

Ingress represents the attacker's first successful interaction with the target environment. This phase is primarily focused on abusing human trust, software trust, or hardware trust. Ingress mechanisms include removable media, malvertising, supply chain compromise, credential abuse, malicious USB devices, and watering hole attacks.

Key outputs of this phase include:

- Initial execution context
- Trust boundary penetration
- User or service privilege level

Ingress methods includes:

- Removable Media & File Transfer 
- Malvertising & Drive-By Downloads 
- Supply Chain Compromise 
- Credential Abuse 
- Malicious or Compromised USB Devices
- Watering Hole Attacks 
- External Remote 
- Cross-Capability 

Ingress decisions heavily influence the attacker's stealth and options in later phases.

##**MC-ACT** Activation - Execution Capability

Activation converts access into action. This phase determines how and where attacker-controlled logic is executed within the target environment.

Activation includes user-executed files, script-based activation, service execution, DLL side-loading, WMI execution, boot or firmware execution, and browser extension abuse.

Activation outputs include:

- Running malicious logic
- Memory residency
- Privilege escalation opportunities

Activation methods includes:

- User-Executed Files
- Script-Based Activation
- Service-Based Execution
- DLL Side-Loading
- WMI-Based Execution
- Browser Extension Execution
- Boot / Firmware Execution

Activation is often chained with concealment techniques to minimize detection.

##**MC-ANC** Anchoring - Persistence Capability

Anchoring ensures that attacker access survives reboots, logouts, and routine system maintenance. Persistence is not a single technique but a reliability strategy. Anchoring methods include:

- Startup & Logon Execution
- Scheduled & Triggered Execution
- Service & Daemon Persistence
- Registry-Based Persistence
- Browser-Based Persistence
- WMI & Event Subscription Persistence
- Fileless & In-Memory Persistence
- Boot & Pre-OS Persistence

The primary output of anchoring is long-term operational presence with minimal reinfection cost.

##**MC-CON** Concealment - Defense Evasion Capability

Concealment reduces the likelihood that malicious activity will be detected, analyzed, or responded to. This phase actively degrades defender visibility and confidence.

Concealment techniques include:

- Obfuscation & Packing
- Fileless Malware Execution
- Security Tool Tampering
- Masquerading & Impersonation
- Environment & Sandbox Evasion
- Process Injection
- Polymorphism & Metamorphism
- Log & Artifact Manipulation
- Living-off-the-Land for Evasion
- Anti-Forensics & Cleanup

Concealment enables extended dwell time and increases the success of expansion and extraction.

##**MC-EXP** Expansion - Lateral Movement Capability

Expansion focuses on increasing the attacker's control surface inside the environment. This phase transforms a single compromised system into organizational compromise.

Expansion techniques include:

- Living-off-the-Land Lateral Movement
- Credential Reuse & Relay
- Pass-the-Hash / Pass-the-Ticket
- Remote Service & Protocol Abuse
- Network Share Propagation
- Worm-like Self-Propagation
- Privilege Escalation Across Hosts
- Identity & Trust Relationship Abuse
- Directory Services Targeting
- Cloud & Hybrid Lateral Movement

Outputs include additional hosts, elevated privileges, and increased operational resilience.

##**MC-EXT** Extraction - Exfiltration & Control Capability

Extraction is where attackers realize value from their intrusion. This includes data theft, continuous command and control, and operational leverage.

Extraction channels include:

- HTTP / HTTPS Data Exfiltration
- DNS Tunneling
- Cloud Storage Abuse
- Messaging and Social Platform Channels
- FTP / SFTP / FTPS Transfer
- Tor / Proxy / VPN Anonymization Channels
- Encrypted Command-and-Control Channels
- Removable Media Data Extraction
- Stenographic Data Transfer
- Multi-Channel Redundant Exfiltration

Extraction may occur incrementally throughout the intrusion rather than only at the end.

## Unified Sub Phases table

| Ingress                              | Activation                  | Anchoring                            | Concealment                     | Expansion                            | Extraction                               |
| ------------------------------------ | --------------------------- | ------------------------------------ | ------------------------------- | ------------------------------------ | ---------------------------------------- |
| Removable Media & File Transfer      | User-Executed Files         | Startup & Logon Execution            | Obfuscation & Packing           | Living-off-the-Land Lateral Movement | HTTP / HTTPS Data Exfiltration           |
| Malvertising & Drive-By Downloads    | Script-Based Activation     | Scheduled & Triggered Execution      | Fileless Malware Execution      | Credential Reuse & Relay             | DNS Tunneling                            |
| Supply Chain Compromise              | Service-Based Execution     | Service & Daemon Persistence         | Security Tool Tampering         | Pass-the-Hash / Pass-the-Ticket      | Cloud Storage Abuse                      |
| Credential Abuse                     | DLL Side-Loading            | Registry-Based Persistence           | Masquerading & Impersonation    | Remote Service & Protocol Abuse      | Messaging and Social Platform Channels   |
| Malicious or Compromised USB Devices | WMI-Based Execution         | Browser-Based Persistence            | Environment & Sandbox Evasion   | Network Share Propagation            | FTP / SFTP / FTPS Transfer               |
| Watering Hole Attacks                | Browser Extension Execution | WMI & Event Subscription Persistence | Process Injection               | Worm-like Self-Propagation           | Tor / Proxy / VPN Anonymization Channels |
| External Remote                      | Boot / Firmware Execution   | Fileless & In-Memory Persistence     | Polymorphism & Metamorphism     | Privilege Escalation Across Hosts    | Encrypted Command-and-Control Channels   |
| Cross-Capability                     |                             | Boot & Pre-OS Persistence            | Log & Artifact Manipulation     | Identity & Trust Relationship Abuse  | Removable Media Data Extraction          |
|                                      |                             |                                      | Living-off-the-Land for Evasion | Directory Services Targeting         | Stenographic Data Transfer               |
|                                      |                             |                                      | Anti-Forensics & Cleanup        | Cloud & Hybrid Lateral Movement      | Multi-Channel Redundant Exfiltration     |
