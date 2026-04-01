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