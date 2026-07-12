# EXT-05 · FTP / SFTP / FTPS Transfer

**Phase:** [Extraction](../ext.md) · Exfiltration & C2  |  **Detections:** KQL

[← Back to Extraction](../ext.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

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

## Detection Guidance

Detection relies on monitoring file transfer activity, connection behavior, and data movement patterns associated with file transfer protocols. Contextual correlation between file access and network activity is essential to reduce false positives.

* Monitor connections to external file transfer servers  
* Detect large or unusual file upload or download activity  
* Correlate file transfer events with sensitive data access  
* Alert on automated transfer jobs outside approved schedules  
* Identify rare or unauthorized file transfer connections

## KQL Detection Concepts

* Network events indicating connections to FTP or SFTP servers  
* File transfer activity associated with external destinations  
* Authentication events involving file transfer accounts

## YARA Detection Concepts

* Scripts or binaries implementing automated file transfer routines  
* Code patterns associated with FTP or SFTP communication  
* Executable components transferring files to remote servers

## KQL Detection Rule

```kql
// FTP/SFTP/FTPS Transfer: command-line FTP clients to external hosts
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ftp.exe","winscp.com","winscp.exe","pscp.exe","psftp.exe","curl.exe") and ProcessCommandLine has_any ("ftp://","sftp://","ftps://","-put","put ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Restrict access to external file transfer services  
* Monitor file transfer activity and enforce transfer policies  
* Implement data loss prevention controls for outbound transfers  
* Enforce strong authentication for file transfer accounts

## Incident Response

* Identify systems involved in unauthorized file transfer activity  
* Block connections to suspicious file transfer servers  
* Analyze transferred files and associated system behavior  
* Review transfer logs and communication timelines

## Chain Linking

`EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables next:**

- [Tor / Proxy / VPN Anonymization Channels](../ext/MC-EXT-06.md) (`EXT-06`)
- [Encrypted Command-and-Control Channels](../ext/MC-EXT-07.md) (`EXT-07`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Messaging and Social Platform Channels](../ext/MC-EXT-04.md) | [Tor / Proxy / VPN Anonymization Channels →](../ext/MC-EXT-06.md)
