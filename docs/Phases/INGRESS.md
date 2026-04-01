## INGRESS

## Phase Overview

The INGRESS phase encompasses all techniques and capabilities that result in an attacker gaining an initial foothold within an environment. Unlike later phases, INGRESS focuses on entry, trust establishment, and delivery of access rather than execution logic. The transition from INGRESS to ACTIVATION occurs when attacker-controlled logic can be executed. This transition point is critical for detection and disruption.  
  
INGRESS ends when execution becomes possible, at which point ACTIVATION begins. INGRESS capabilities are defined by the type of trust abused:

*   Human trust (users, credentials)
*   Software trust (updates, dependencies)
*   Hardware trust (peripherals)
*   Network trust (remote services)
*   Web trust (advertising, websites)

Defensive efforts during INGRESS should prioritize visibility into:

*   Identity authentication
*   Software integrity
*   Peripheral activity
*   Web and network exposure

Removable Media & File Transfer - This capability introduces attacker-controlled artifacts via physical or logical transfer. Execution typically depends on user interaction, making awareness and device controls critical.

Malvertising & Drive-By Downloads - This capability abuses the web ecosystem to silently deliver malicious content. Attackers leverage browser trust, advertising platforms, and redirect chains.

Supply Chain Compromise - Supply chain compromise weaponized trust in vendors, software updates, and dependencies. This capability enables high-trust delivery and often bypasses traditional security controls.

Credential Abuse - Credential abuse leverages valid authentication material to gain authorized access. This capability often bypasses perimeter defenses and directly enables execution.

Malicious or Compromised USB Devices - Peripheral trust abuse allows attackers to introduce execution logic through device classes such as HID, storage, or network adapters, often with minimal user interaction.

Watering Hole Attacks - Watering hole attacks compromise trusted websites to deliver malicious content selectively to high-value targets, reducing exposure and detection.

External Remote Services - External remote services ingress exploits exposed VPNs, RDP, cloud portals, and SaaS platforms to gain authenticated or network-level access.

Cross-Capability Relationships - INGRESS capabilities often overlap and reinforce one another. For example, credential abuse may follow malvertising, or supply chain compromise may enable remote service abuse.

## Removable Media & File Transfer:

**Summary:**

Removable Media & File Transfer refers to the introduction of attacker-controlled content into a target environment via portable storage devices or ad-hoc file transfer methods. This includes USB drives, external hard disks, shared folders, peer-to-peer transfers, and informal file exchange channels. Within MalChain, this capability ends once content is delivered and an execution opportunity exists. Attackers exploit implicit trust in physical media and informal file sharing. Human curiosity, convenience, and operational pressure often bypass security controls. Trust abuse may involve labeled media, disguised documents, or files presented as legitimate tools. Common delivery methods include:

*   USB flash drives
*   External HDDs or SSDs
*   Network shares
*   Email-based file transfer
*   Ad-hoc cloud sharing links

Real world usage includes:

*   Targeted espionage campaigns
*   Industrial control system attacks
*   Air-gapped environment breaches
*   Opportunistic malware spread

**Detection:**

Detection relies on monitoring device connection events, file creation telemetry, and abnormal execution patterns originating from removable media. Contextual correlation is essential to reduce false positives.

*   Monitor removable media mount events
*   Detect executable creation on external drives
*   Correlate file access with execution attempts
*   Alert on shortcut execution from removable paths
*   Identify rare file types transferred via media

**KQL** **Detection Concepts:**

*   File creation events where DriveType is Removable
*   Process execution originating from removable volumes
*   LNK execution referencing external media paths

**YARA** **Detection Concepts:**

*   Malicious LNK structures
*   Embedded payloads in documents
*   Auto-execution logic

**Mitigation:**

*   Disable autorun features
*   Enforce removable media policies
*   Scan external drives on insertion
*   Educate users on media risks

**Incident response:**

*   Identify all accessed files
*   Quarantine affected endpoints
*   Analyze transferred artifacts
*   Review execution timelines

**Linking:**

*   User-Executed Files
*   Script-Based Activation
*   DLL Side-Loading

## Malvertising & Drive-By Downloads:

**Summary:**

Malvertising & Drive-By Downloads refer to the delivery of malicious content through compromised or malicious online advertisements and websites. Victims may receive malware without knowingly downloading files, as exploitation occurs through browser interactions, redirect chains, or exploit kits. Within MalChain, this capability ends once a payload is delivered or execution becomes possible. Attackers abuse trust in:

*   Legitimate advertising networks
*   Popular websites
*   Browser security assumptions

Victims often do not realize exposure has occurred, increasing dwell time. Common delivery mechanisms include:

*   Malicious ad creatives
*   Redirect chains
*   Exploit kits
*   Fake update prompts
*   Browser plugin abuse

Real world usage includes:

*   Banking Trojans
*   Ransomware loaders
*   Information stealers
*   Cryptocurrency miners

**Detection:**

Detection relies on browser telemetry, network traffic analysis, and correlation between web activity and subsequent file or script execution. Early detection significantly reduces downstream impact.

*   Monitor browser redirect chains
*   Detect anomalous JavaScript execution
*   Identify unexpected file downloads
*   Alert on fake update indicators
*   Correlate web activity with execution events

**KQL Detection Concepts:**

*   Browser process initiating file downloads
*   JavaScript execution followed by process creation
*   Network connections to newly registered domains

**YARA Detection Concepts:**

*   Exploit kit fingerprints
*   Obfuscated JavaScript loaders
*   Suspicious redirect logic

**Mitigation:**

*   Use ad-blocking and script control
*   Harden browser configurations
*   Disable unnecessary plugins
*   Enforce patch management

**Incident response:**

*   Review browser history and cache
*   Identify downloaded artifacts
*   Isolate affected endpoints
*   Hunt for follow-on execution

**Linking:**

*   Script-Based Activation
*   User-Executed Files
*   DLL Side-Loading

## Supply Chain Compromise:

**Summary:**

Supply Chain Compromise refers to initial access gained through the manipulation, poisoning, or compromise of third-party software, hardware, services, or dependencies that are trusted by the target organization. In MalChain, this capability ends once malicious code or access is delivered through a trusted channel and execution becomes possible. Attackers exploit institutional trust placed in:

*   Software vendors
*   Update mechanisms
*   Open-source dependencies
*   Managed service providers
*   Hardware suppliers

Because trust is pre-established, detection is often delayed. Attack vectors include:

*   Trojanized software updates
*   Compromised build pipelines
*   Dependency confusion attacks
*   Backdoored libraries
*   Malicious firmware or hardware components

The real world usage includes:

*   Espionage campaigns
*   Large-scale ransomware operations
*   Open-source ecosystem abuse
*   Hardware and firmware backdoors

**Detection:**

Detection focuses on integrity validation, anomaly detection, and monitoring trusted update channels for deviations. Traditional signature-based detection is often ineffective.

*   Validate software and update signatures
*   Monitor update behavior anomalies
*   Detect unexpected network destinations during updates
*   Track dependency version changes
*   Correlate trusted updates with execution events

**KQL Detection Concepts:**

*   Execution triggered by update services
*   Network traffic to non-standard update domains
*   Signed binaries exhibiting anomalous behavior

**YARA Detection Concepts:**

*   Embedded backdoor logic
*   Unexpected network routines
*   Hardcoded command-and-control indicators

**Mitigation:**

*   Enforce code signing and verification
*   Pin dependency versions
*   Audit vendor security posture
*   Monitor build pipelines

**Incident response:**

*   Identify scope of affected assets
*   Validate integrity of software artifacts
*   Revoke compromised trust relationships
*   Coordinate with vendors and partners

**Linking:**

*   Service-Based Execution
*   DLL Side-Loading
*   Stealthy Persistence

## Credential Abuse:

**Summary:**

Credential Abuse refers to the use of valid authentication material obtained through theft, guessing, reuse, or compromise to gain unauthorized access. Unlike exploitation-based ingress, credential abuse leverages legitimate authentication mechanisms. Within MalChain, this capability ends once authenticated access is achieved and execution opportunities become available. Attackers exploit trust placed in:
	
*   Username/password authentication
*   Session tokens and cookies
*   API keys and secrets
*   Federated identity systems
  
Successful authentication often bypasses perimeter defenses entirely. Common abuse patterns include:
	
*   Phishing-derived credential use
*   Password spraying
*   Credential stuffing
*   Reuse of leaked credentials
*   Abuse of service accounts
  
Real world usage includes:

*   Ransomware initial access
*   Cloud account takeover campaigns
*   Business email compromise
*   Advanced persistent threat operations
  
**Detection:**

Detection relies on authentication telemetry, behavioral baselining, and correlation across identity, endpoint, and network signals. Detection strategies includes:
	
*   Detect anomalous login patterns
*   Monitor failed-to-success login sequences
*   Identify impossible travel scenarios
*   Alert on credential use outside business hours
*   Detect service account misuse
  
**KQL Detection Concepts:**

*   Multiple authentication attempts from a single IP
*   Successful login after multiple failures
*   Login from rare geographic locations
  
**YARA Detection Concepts:**

*   Embedded credentials in malware
*   Hardcoded API tokens
*   Credential harvesting routines
  
**Mitigation:**

*   Enforce strong password policies
*   Enable multi-factor authentication
*   Monitor and rotate credentials
*   Limit service account privileges
  
**Incident response:**

*   Reset compromised credentials
*   Invalidate sessions and tokens
*   Review accessed resources
*   Hunt for follow-on execution
  
**Linking:**

*   Service-Based Execution
*   WMI-Based Execution
*   Cloud Resource Abuse
  
## Malicious or Compromised USB Devices:

**Summary:**

Malicious or Compromised USB Devices refer to physical peripherals that present themselves as legitimate hardware (storage, keyboard, network adapter) while executing attacker-controlled logic. These devices may contain modified firmware or embedded microcontrollers. Within MalChain, this capability ends once device interaction results in system-level access or execution opportunity. Attackers exploit:
	
*   Implicit trust in USB devices
*   Automatic driver installation
*   Human curiosity and convenience
*   Limited firmware inspection
  
Device identity is assumed rather than verified. Observed attack patterns include:

*   HID emulation (keyboard injection)
*   USB network adapter spoofing
*   Firmware-flashed storage devices
*   Composite device masquerading
  
The real world usage includes:

*   Targeted espionage operations
*   Red team simulation frameworks
*   Air-gapped network attacks
*   Physical intrusion campaigns
  
**Detection:**

Detection focuses on device enumeration events, driver installation logs, and abnormal behavior following peripheral insertion. Visibility into USB class and firmware behavior is critical.

*   Monitor new USB device enumeration
*   Detect HID devices attached unexpectedly
*   Alert on USB-triggered command execution
*   Identify new network interfaces via USB
*   Correlate device insertion with execution events
  
**KQL Detection Concepts:**

*   USB device insertion events
*   New HID or network device detection
*   Process execution shortly after USB insertion
  
**YARA Detection Concepts:**

*   HID attack scripts
*   Embedded payload logic
*   Peripheral-triggered loaders
  
**Mitigation:**

*   Restrict USB device classes
*   Disable automatic driver installation
*   Enforce device control policies
*   Use hardware whitelisting
  
**Incident response:**

*   Physically secure and isolate device
*   Identify injected commands or payloads
*   Review system changes post-insertion
*   Hunt for follow-on execution
  
**Linking:**

*   Script-Based Activation
*   User-Executed Files
*   Credential Abuse
  
## Watering Hole Attacks:

**Summary:**

Watering Hole Attacks refer to the compromise of websites, portals, or online services that are trusted and frequently accessed by a target population. Attackers inject malicious scripts or redirect logic to deliver payloads selectively. Within MalChain, this capability ends once malicious content is delivered or execution becomes possible. Attackers exploit trust in:

*   Industry-specific websites
*   Internal portals and partner sites
*   Community forums
*   Vendor documentation pages
  
Victims rarely suspect compromise of familiar resources. Watering hole campaigns rely on profiling to maximize effectiveness:

*   IP range filtering
*   User-agent inspection
*   Geolocation checks
*   Time-based activation
  
The real world usage includes:

*   Espionage-focused APT groups
*   Long-term surveillance campaigns
*   Targeted credential harvesting operations
  
**Detection:**

Detection requires visibility into web traffic, script execution, and correlation between visited sites and subsequent execution events. Because delivery is selective, detection often relies on anomaly hunting.

*   Monitor web traffic to rarely compromised sites
*   Detect injected or modified JavaScript
*   Identify browser redirects to unknown domains
*   Correlate site visits with execution events
*   Monitor selective targeting behavior
  
**KQL Detection Concepts:**

*   Browser process contacting rare domains after known site visits
*   JavaScript execution followed by payload download
*   Redirect chains tied to specific user groups
  
**YARA Detection Concepts:**

*   Malicious JavaScript loaders
*   Conditional execution logic
*   Obfuscated redirect scripts
  
**Mitigation:**

*   Enforce content security policies
*   Monitor integrity of trusted websites
*   Use browser isolation technologies
*   Educate users on targeted web risks
  
**Incident response:**

*   Identify affected users and systems
*   Capture browser artifacts and cache
*   Coordinate with site owners
*   Hunt for follow-on execution
  
**Linking:**

*   Script-Based Activation
*   Credential Abuse
*   DLL Side-Loading
  
## External Remote Services:

**Summary:**

External Remote Services ingress occurs when attackers gain access through internet-facing services that are designed for legitimate remote connectivity. These include VPNs, RDP, VDI platforms, SSH, cloud admin portals, and SaaS applications. Within MalChain, this capability ends once authenticated or network-level access is established. Attackers exploit trust in:
	
*   Remote access infrastructure
*   Cloud identity providers
*   MFA fatigue or misconfiguration
*   Legacy authentication protocols
  
Observed abuse patterns include:

*   VPN credential compromise
*   RDP brute force or reuse
*   SaaS account takeover
*   API token misuse
  
The real world usage includes:

*   Ransomware intrusions
*   Cloud account takeover campaigns
*   Initial access broker operations
  
**Detection:**

Detection relies on remote access logs, identity telemetry, and correlation with endpoint execution events.

*   Monitor anomalous VPN logins
*   Detect RDP access from rare locations
*   Alert on MFA fatigue patterns
*   Monitor SaaS admin activity
*   Correlate remote login with execution
  
**KQL Detection Concepts:**

*   Successful VPN login followed by process creation
*   RDP session start preceding execution events
*   Cloud admin actions outside baseline behavior
  
**YARA Detection Concepts:**

*   Remote execution stagers
*   Credential harvesting logic
*   Cloud abuse tooling
  
**Mitigation:**

*   Enforce MFA everywhere
*   Restrict exposed services
*   Monitor remote access posture
*   Implement conditional access
  
**Incident response:**

*   Revoke compromised sessions
*   Reset affected credentials
*   Review accessed systems
*   Hunt for persistence and lateral movement
  
**Linking:**

*   Service-Based Execution
*   Credential Abuse
*   Lateral Movement
