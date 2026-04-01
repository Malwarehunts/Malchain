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
