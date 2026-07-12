# Chain Linking

How actions in one phase enable the next, forming a deterministic chain from initial access to impact. Each capability shows the state transition it produces and the techniques it most commonly enables.

[← Home](../README.md) · [Framework Overview](OVERVIEW.md)

## Ingress

### [ING-01 · Removable Media & File Transfer](phases/ing/MC-ING-01.md)

**Linkage:** `INGRESS → Media Delivery → Trust Establishment → ACTIVATION`

**Enables:**
- [User-Executed Files](phases/act/MC-ACT-01.md) (`ACT-01`)
- [Script-Based Execution](phases/act/MC-ACT-02.md) (`ACT-02`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)

### [ING-02 · Malvertising & Drive-By Downloads](phases/ing/MC-ING-02.md)

**Linkage:** `INGRESS → Web Exposure → Silent Payload Delivery → ACTIVATION`

**Enables:**
- [Script-Based Execution](phases/act/MC-ACT-02.md) (`ACT-02`)
- [User-Executed Files](phases/act/MC-ACT-01.md) (`ACT-01`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)

### [ING-03 · Supply Chain Compromise](phases/ing/MC-ING-03.md)

**Linkage:** `INGRESS → Trusted Update or Dependency → ACTIVATION`

**Enables:**
- [Service-Based Execution](phases/act/MC-ACT-03.md) (`ACT-03`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)
- [Fileless & In-Memory Persistence](phases/anc/MC-ANC-07.md) (`ANC-07`)

### [ING-04 · Credential Abuse](phases/ing/MC-ING-04.md)

**Linkage:** `INGRESS → Authenticated Access → ACTIVATION`

**Enables:**
- [Service-Based Execution](phases/act/MC-ACT-03.md) (`ACT-03`)
- [WMI-Based Execution](phases/act/MC-ACT-05.md) (`ACT-05`)
- [Cloud & Hybrid Lateral Movement](phases/exp/MC-EXP-10.md) (`EXP-10`)

### [ING-05 · Malicious or Compromised USB Devices](phases/ing/MC-ING-05.md)

**Linkage:** `INGRESS → Peripheral Trust → Automatic Device Execution → ACTIVATION`

**Enables:**
- [Script-Based Execution](phases/act/MC-ACT-02.md) (`ACT-02`)
- [User-Executed Files](phases/act/MC-ACT-01.md) (`ACT-01`)
- [Credential Abuse](phases/ing/MC-ING-04.md) (`ING-04`)

### [ING-06 · Watering Hole Attacks](phases/ing/MC-ING-06.md)

**Linkage:** `INGRESS → Targeted Web Exposure → ACTIVATION`

**Enables:**
- [Script-Based Execution](phases/act/MC-ACT-02.md) (`ACT-02`)
- [Credential Abuse](phases/ing/MC-ING-04.md) (`ING-04`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)

### [ING-07 · External Remote Services](phases/ing/MC-ING-07.md)

**Linkage:** `INGRESS → Authenticated Remote Access → ACTIVATION`

**Enables:**
- [Service-Based Execution](phases/act/MC-ACT-03.md) (`ACT-03`)
- [Credential Abuse](phases/ing/MC-ING-04.md) (`ING-04`)
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)

## Activation

### [ACT-01 · User-Executed Files](phases/act/MC-ACT-01.md)

**Linkage:** `ACTIVATION → Code Executing → reinforced within ACTIVATION`

**Enables:**
- [Script-Based Execution](phases/act/MC-ACT-02.md) (`ACT-02`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)
- [Startup & Logon Execution](phases/anc/MC-ANC-01.md) (`ANC-01`)

### [ACT-02 · Script-Based Execution](phases/act/MC-ACT-02.md)

**Linkage:** `ACTIVATION → Code Executing → reinforced within ACTIVATION`

**Enables:**
- [Service-Based Execution](phases/act/MC-ACT-03.md) (`ACT-03`)
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)
- [Scheduled & Triggered Execution](phases/anc/MC-ANC-02.md) (`ANC-02`)

### [ACT-03 · Service-Based Execution](phases/act/MC-ACT-03.md)

**Linkage:** `ACTIVATION → Code Executing → ANCHORING`

**Enables:**
- [DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md) (`ACT-04`)
- [Scheduled & Triggered Execution](phases/anc/MC-ANC-02.md) (`ANC-02`)
- [Service & Daemon Persistence](phases/anc/MC-ANC-03.md) (`ANC-03`)

### [ACT-04 · DLL Side-Loading or Hijacking](phases/act/MC-ACT-04.md)

**Linkage:** `ACTIVATION → Code Executing → CONCEALMENT`

**Enables:**
- [WMI-Based Execution](phases/act/MC-ACT-05.md) (`ACT-05`)
- [Registry-Based Persistence](phases/anc/MC-ANC-04.md) (`ANC-04`)
- [Process Injection](phases/con/MC-CON-06.md) (`CON-06`)

### [ACT-05 · WMI-Based Execution](phases/act/MC-ACT-05.md)

**Linkage:** `ACTIVATION → Code Executing → EXPANSION`

**Enables:**
- [Browser Extension Execution](phases/act/MC-ACT-06.md) (`ACT-06`)
- [WMI & Event Subscription Persistence](phases/anc/MC-ANC-06.md) (`ANC-06`)
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)

### [ACT-06 · Browser Extension Execution](phases/act/MC-ACT-06.md)

**Linkage:** `ACTIVATION → Code Executing → EXTRACTION`

**Enables:**
- [Boot / Firmware Execution](phases/act/MC-ACT-07.md) (`ACT-07`)
- [Browser-Based Persistence](phases/anc/MC-ANC-05.md) (`ANC-05`)
- [Messaging and Social Platform Channels](phases/ext/MC-EXT-04.md) (`EXT-04`)

### [ACT-07 · Boot / Firmware Execution](phases/act/MC-ACT-07.md)

**Linkage:** `ACTIVATION → Code Executing → ANCHORING`

**Enables:**
- [Startup & Logon Execution](phases/anc/MC-ANC-01.md) (`ANC-01`)
- [Boot & Pre-OS Persistence](phases/anc/MC-ANC-08.md) (`ANC-08`)
- [Environment & Sandbox Evasion](phases/con/MC-CON-05.md) (`CON-05`)

## Anchoring

### [ANC-01 · Startup & Logon Execution](phases/anc/MC-ANC-01.md)

**Linkage:** `ANCHORING → Presence Assured → reinforced within ANCHORING`

**Enables:**
- [Scheduled & Triggered Execution](phases/anc/MC-ANC-02.md) (`ANC-02`)
- [Registry-Based Persistence](phases/anc/MC-ANC-04.md) (`ANC-04`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)

### [ANC-02 · Scheduled & Triggered Execution](phases/anc/MC-ANC-02.md)

**Linkage:** `ANCHORING → Presence Assured → reinforced within ANCHORING`

**Enables:**
- [Service & Daemon Persistence](phases/anc/MC-ANC-03.md) (`ANC-03`)
- [Registry-Based Persistence](phases/anc/MC-ANC-04.md) (`ANC-04`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)

### [ANC-03 · Service & Daemon Persistence](phases/anc/MC-ANC-03.md)

**Linkage:** `ANCHORING → Presence Assured → CONCEALMENT`

**Enables:**
- [Registry-Based Persistence](phases/anc/MC-ANC-04.md) (`ANC-04`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Remote Service & Protocol Abuse](phases/exp/MC-EXP-04.md) (`EXP-04`)

### [ANC-04 · Registry-Based Persistence](phases/anc/MC-ANC-04.md)

**Linkage:** `ANCHORING → Presence Assured → CONCEALMENT`

**Enables:**
- [Browser-Based Persistence](phases/anc/MC-ANC-05.md) (`ANC-05`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)

### [ANC-05 · Browser-Based Persistence](phases/anc/MC-ANC-05.md)

**Linkage:** `ANCHORING → Presence Assured → EXTRACTION`

**Enables:**
- [WMI & Event Subscription Persistence](phases/anc/MC-ANC-06.md) (`ANC-06`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Messaging and Social Platform Channels](phases/ext/MC-EXT-04.md) (`EXT-04`)

### [ANC-06 · WMI & Event Subscription Persistence](phases/anc/MC-ANC-06.md)

**Linkage:** `ANCHORING → Presence Assured → CONCEALMENT`

**Enables:**
- [Fileless & In-Memory Persistence](phases/anc/MC-ANC-07.md) (`ANC-07`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)

### [ANC-07 · Fileless & In-Memory Persistence](phases/anc/MC-ANC-07.md)

**Linkage:** `ANCHORING → Presence Assured → EXTRACTION`

**Enables:**
- [Boot & Pre-OS Persistence](phases/anc/MC-ANC-08.md) (`ANC-08`)
- [Process Injection](phases/con/MC-CON-06.md) (`CON-06`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)

### [ANC-08 · Boot & Pre-OS Persistence](phases/anc/MC-ANC-08.md)

**Linkage:** `ANCHORING → Presence Assured → CONCEALMENT`

**Enables:**
- [Obfuscation & Packing](phases/con/MC-CON-01.md) (`CON-01`)
- [Environment & Sandbox Evasion](phases/con/MC-CON-05.md) (`CON-05`)
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)

## Concealment

### [CON-01 · Obfuscation & Packing](phases/con/MC-CON-01.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Fileless Malware Execution](phases/con/MC-CON-02.md) (`CON-02`)
- [Process Injection](phases/con/MC-CON-06.md) (`CON-06`)
- [Polymorphism & Metamorphism](phases/con/MC-CON-07.md) (`CON-07`)

### [CON-02 · Fileless Malware Execution](phases/con/MC-CON-02.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Security Tool Tampering](phases/con/MC-CON-03.md) (`CON-03`)
- [Process Injection](phases/con/MC-CON-06.md) (`CON-06`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)

### [CON-03 · Security Tool Tampering](phases/con/MC-CON-03.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Masquerading & Impersonation](phases/con/MC-CON-04.md) (`CON-04`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)

### [CON-04 · Masquerading & Impersonation](phases/con/MC-CON-04.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Environment & Sandbox Evasion](phases/con/MC-CON-05.md) (`CON-05`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)

### [CON-05 · Environment & Sandbox Evasion](phases/con/MC-CON-05.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Process Injection](phases/con/MC-CON-06.md) (`CON-06`)
- [Polymorphism & Metamorphism](phases/con/MC-CON-07.md) (`CON-07`)
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)

### [CON-06 · Process Injection](phases/con/MC-CON-06.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Polymorphism & Metamorphism](phases/con/MC-CON-07.md) (`CON-07`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)

### [CON-07 · Polymorphism & Metamorphism](phases/con/MC-CON-07.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [CON-08 · Log & Artifact Manipulation](phases/con/MC-CON-08.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables:**
- [Living-off-the-Land for Evasion](phases/con/MC-CON-09.md) (`CON-09`)
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [CON-09 · Living-off-the-Land for Evasion](phases/con/MC-CON-09.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → EXTRACTION`

**Enables:**
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [CON-10 · Anti-Forensics & Cleanup](phases/con/MC-CON-10.md)

**Linkage:** `CONCEALMENT → Visibility Degraded → EXTRACTION`

**Enables:**
- [Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md) (`EXP-01`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)
- [Log & Artifact Manipulation](phases/con/MC-CON-08.md) (`CON-08`)

## Expansion

### [EXP-01 · Living-off-the-Land Lateral Movement](phases/exp/MC-EXP-01.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Credential Reuse & Relay](phases/exp/MC-EXP-02.md) (`EXP-02`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)
- [HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md) (`EXT-01`)

### [EXP-02 · Credential Reuse & Relay](phases/exp/MC-EXP-02.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Pass-the-Hash / Pass-the-Ticket](phases/exp/MC-EXP-03.md) (`EXP-03`)
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)
- [DNS Tunneling](phases/ext/MC-EXT-02.md) (`EXT-02`)

### [EXP-03 · Pass-the-Hash / Pass-the-Ticket](phases/exp/MC-EXP-03.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Remote Service & Protocol Abuse](phases/exp/MC-EXP-04.md) (`EXP-04`)
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)

### [EXP-04 · Remote Service & Protocol Abuse](phases/exp/MC-EXP-04.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Network Share Propagation](phases/exp/MC-EXP-05.md) (`EXP-05`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)
- [HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md) (`EXT-01`)

### [EXP-05 · Network Share Propagation](phases/exp/MC-EXP-05.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Worm-like Self-Propagation](phases/exp/MC-EXP-06.md) (`EXP-06`)
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)
- [FTP / SFTP / FTPS Transfer](phases/ext/MC-EXT-05.md) (`EXT-05`)

### [EXP-06 · Worm-like Self-Propagation](phases/exp/MC-EXP-06.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md) (`EXP-07`)
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXP-07 · Privilege Escalation Across Hosts](phases/exp/MC-EXP-07.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md) (`EXP-08`)
- [Directory Services Targeting](phases/exp/MC-EXP-09.md) (`EXP-09`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)

### [EXP-08 · Identity & Trust Relationship Abuse](phases/exp/MC-EXP-08.md)

**Linkage:** `EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables:**
- [Directory Services Targeting](phases/exp/MC-EXP-09.md) (`EXP-09`)
- [Cloud & Hybrid Lateral Movement](phases/exp/MC-EXP-10.md) (`EXP-10`)
- [HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md) (`EXT-01`)

### [EXP-09 · Directory Services Targeting](phases/exp/MC-EXP-09.md)

**Linkage:** `EXPANSION → Foothold Widened → EXTRACTION`

**Enables:**
- [Cloud & Hybrid Lateral Movement](phases/exp/MC-EXP-10.md) (`EXP-10`)
- [Messaging and Social Platform Channels](phases/ext/MC-EXT-04.md) (`EXT-04`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)

### [EXP-10 · Cloud & Hybrid Lateral Movement](phases/exp/MC-EXP-10.md)

**Linkage:** `EXPANSION → Foothold Widened → EXTRACTION`

**Enables:**
- [HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md) (`EXT-01`)
- [Cloud Storage Abuse](phases/ext/MC-EXT-03.md) (`EXT-03`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

## Extraction

### [EXT-01 · HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [DNS Tunneling](phases/ext/MC-EXT-02.md) (`EXT-02`)
- [Cloud Storage Abuse](phases/ext/MC-EXT-03.md) (`EXT-03`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-02 · DNS Tunneling](phases/ext/MC-EXT-02.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Cloud Storage Abuse](phases/ext/MC-EXT-03.md) (`EXT-03`)
- [Tor / Proxy / VPN Anonymization Channels](phases/ext/MC-EXT-06.md) (`EXT-06`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-03 · Cloud Storage Abuse](phases/ext/MC-EXT-03.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Messaging and Social Platform Channels](phases/ext/MC-EXT-04.md) (`EXT-04`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-04 · Messaging and Social Platform Channels](phases/ext/MC-EXT-04.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [FTP / SFTP / FTPS Transfer](phases/ext/MC-EXT-05.md) (`EXT-05`)
- [Tor / Proxy / VPN Anonymization Channels](phases/ext/MC-EXT-06.md) (`EXT-06`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-05 · FTP / SFTP / FTPS Transfer](phases/ext/MC-EXT-05.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Tor / Proxy / VPN Anonymization Channels](phases/ext/MC-EXT-06.md) (`EXT-06`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-06 · Tor / Proxy / VPN Anonymization Channels](phases/ext/MC-EXT-06.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)

### [EXT-07 · Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Removable Media Data Extraction](phases/ext/MC-EXT-08.md) (`EXT-08`)
- [Steganographic Data Transfer](phases/ext/MC-EXT-09.md) (`EXT-09`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)

### [EXT-08 · Removable Media Data Extraction](phases/ext/MC-EXT-08.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Steganographic Data Transfer](phases/ext/MC-EXT-09.md) (`EXT-09`)
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)

### [EXT-09 · Steganographic Data Transfer](phases/ext/MC-EXT-09.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md) (`EXT-10`)
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)
- [HTTP / HTTPS Data Exfiltration](phases/ext/MC-EXT-01.md) (`EXT-01`)

### [EXT-10 · Multi-Channel Redundant Exfiltration](phases/ext/MC-EXT-10.md)

**Linkage:** `EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables:**
- [Anti-Forensics & Cleanup](phases/con/MC-CON-10.md) (`CON-10`)
- [Removable Media Data Extraction](phases/ext/MC-EXT-08.md) (`EXT-08`)
- [Encrypted Command-and-Control Channels](phases/ext/MC-EXT-07.md) (`EXT-07`)
