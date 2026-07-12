# Framework Overview

[← Home](../README.md) · [Chain Linking](LINKING.md) · [Detection Library](DETECTIONS.md) · [About](../ABOUT.md)

---

MalChain is an open-source, behavior-centric malware analysis and detection framework designed to model real-world adversary operations across the full intrusion lifecycle. Unlike indicator-driven or tool-centric models, MalChain focuses on attacker capabilities, trust abuse, and operational chaining.

## Purpose and Scope

The purpose of MalChain is to provide defenders, analysts, and researchers with a structured, high-fidelity model for understanding malware behavior beyond individual tools or campaigns. MalChain abstracts attacker actions into reusable operational capabilities that remain stable even as malware tooling evolves. This framework is intended for:

- Security Operations Centers (SOC)
- Detection engineering teams
- Incident responders
- Malware researchers
- Red and purple teams
- Academic and open-source research

MalChain is platform-agnostic and applies to endpoint, network, cloud, and hybrid environments.

## MalChain Attack Chain Overview

MalChain organizes adversary behavior into six primary phases:

| Phase | Techniques | Focus |
|-------|-----------|-------|
| Ingress  | 7 | How malware enters systems |
| Activation  | 7 | Running malicious code |
| Anchoring  | 8 | Maintaining presence |
| Concealment  | 10 | Avoiding detection |
| Expansion  | 10 | Spreading within networks |
| Extraction  | 10 | Stealing data |
| **Total** | **52** | Full intrusion lifecycle |

Each phase represents a set of attacker objectives and capabilities rather than specific techniques.

## Using MalChain in Practice

Organizations can apply MalChain to:

- Threat modeling exercises
- SOC alert design
- Incident response playbooks
- Purple-team validation
- Malware research documentation

## The six phases


## **[MC-ING](phases/ing.md)** - Ingress - Initial Access Capability

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
- External Remote Services

Ingress decisions heavily influence the attacker's stealth and options in later phases.

## **[MC-ACT](phases/act.md)** - Activation - Execution Capability

Activation converts access into action. This phase determines how and where attacker-controlled logic is executed within the target environment.

Activation includes user-executed files, script-based activation, service execution, DLL side-loading, WMI execution, boot or firmware execution, and browser extension abuse.

Activation outputs include:

- Running malicious logic
- Memory residency
- Privilege escalation opportunities

Activation methods includes:

- User-Executed Files
- Script-Based Execution
- Service-Based Execution
- DLL Side-Loading
- WMI-Based Execution
- Browser Extension Execution
- Boot / Firmware Execution

Activation is often chained with concealment techniques to minimize detection.

## **[MC-ANC](phases/anc.md)** - Anchoring - Persistence Capability

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

## **[MC-CON](phases/con.md)** - Concealment - Defense Evasion Capability

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

## **[MC-EXP](phases/exp.md)** - Expansion - Lateral Movement Capability

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

## **[MC-EXT](phases/ext.md)** - Extraction - Exfiltration & Control Capability

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
- Steganographic Data Transfer
- Multi-Channel Redundant Exfiltration

Extraction may occur incrementally throughout the intrusion rather than only at the end.

## Unified Sub Phases table

| Ingress                              | Activation                  | Anchoring                            | Concealment                     | Expansion                            | Extraction                               |
| ------------------------------------ | --------------------------- | ------------------------------------ | ------------------------------- | ------------------------------------ | ---------------------------------------- |
| Removable Media & File Transfer      | User-Executed Files         | Startup & Logon Execution            | Obfuscation & Packing           | Living-off-the-Land Lateral Movement | HTTP / HTTPS Data Exfiltration           |
| Malvertising & Drive-By Downloads    | Script-Based Execution     | Scheduled & Triggered Execution      | Fileless Malware Execution      | Credential Reuse & Relay             | DNS Tunneling                            |
| Supply Chain Compromise              | Service-Based Execution     | Service & Daemon Persistence         | Security Tool Tampering         | Pass-the-Hash / Pass-the-Ticket      | Cloud Storage Abuse                      |
| Credential Abuse                     | DLL Side-Loading            | Registry-Based Persistence           | Masquerading & Impersonation    | Remote Service & Protocol Abuse      | Messaging and Social Platform Channels   |
| Malicious or Compromised USB Devices | WMI-Based Execution         | Browser-Based Persistence            | Environment & Sandbox Evasion   | Network Share Propagation            | FTP / SFTP / FTPS Transfer               |
| Watering Hole Attacks                | Browser Extension Execution | WMI & Event Subscription Persistence | Process Injection               | Worm-like Self-Propagation           | Tor / Proxy / VPN Anonymization Channels |
| External Remote Services                     | Boot / Firmware Execution   | Fileless & In-Memory Persistence     | Polymorphism & Metamorphism     | Privilege Escalation Across Hosts    | Encrypted Command-and-Control Channels   |
|                     |                             | Boot & Pre-OS Persistence            | Log & Artifact Manipulation     | Identity & Trust Relationship Abuse  | Removable Media Data Extraction          |
|                                      |                             |                                      | Living-off-the-Land for Evasion | Directory Services Targeting         | Steganographic Data Transfer               |
|                                      |                             |                                      | Anti-Forensics & Cleanup        | Cloud & Hybrid Lateral Movement      | Multi-Channel Redundant Exfiltration     |
