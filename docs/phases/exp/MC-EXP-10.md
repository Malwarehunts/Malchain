# EXP-10 · Cloud & Hybrid Lateral Movement

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Cloud & Hybrid Lateral Movement refers to the expansion of attacker-controlled access across cloud services, on-premises infrastructure, and interconnected hybrid environments using identity, synchronization, or management mechanisms. This includes leveraging cloud accounts, service principals, federation services, or synchronization tools to access additional resources beyond the originally compromised system. Within MalChain, this capability begins once attacker-controlled activity successfully transitions between environments using trusted integration points or identity relationships. Attackers exploit implicit trust in cloud identity synchronization, shared credentials, and cross-environment connectivity to broaden operational reach. Routine reliance on hybrid infrastructure and automated synchronization often allows unauthorized access to propagate without immediate detection. Trust abuse may involve misuse of cloud service accounts, unauthorized synchronization of credentials, or manipulation of federation settings presented as legitimate administrative actions. Common movement methods include:

* Using cloud credentials to access additional services or resources  
* Leveraging identity synchronization between on-premises and cloud environments  
* Accessing hybrid management interfaces to control remote systems  
* Reusing service account credentials across environments  
* Executing administrative actions through cloud management consoles  

Real world usage includes:

* Enterprise intrusion campaigns expanding access through cloud infrastructure  
* Ransomware operators targeting hybrid environments for rapid propagation  
* Insider threat scenarios involving unauthorized cloud resource access  
* Persistent threats maintaining control across distributed infrastructure

## Detection Guidance

Detection relies on monitoring cloud authentication activity, synchronization behavior, and cross-environment access patterns associated with hybrid infrastructure. Contextual correlation between identity usage and resource access is essential to reduce false positives.

* Monitor authentication events across cloud and on-premises systems  
* Detect unusual synchronization or federation activity  
* Correlate cloud resource access with unexpected account behavior  
* Alert on administrative actions initiated from unfamiliar locations  
* Identify rare or unauthorized cross-environment access patterns

## KQL Detection Concepts

* Authentication events involving cloud and hybrid infrastructure access  
* Synchronization activity between identity systems  
* Administrative actions performed through cloud management interfaces

## YARA Detection Concepts

* Scripts or binaries interacting with cloud management APIs  
* Code patterns associated with credential synchronization routines  
* Executable components accessing hybrid infrastructure services

## KQL Detection Rule

```kql
// Cloud & Hybrid Lateral Movement: on-prem host reaching cloud IMDS / token endpoints
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("169.254.169.254","login.microsoftonline.com","sts.amazonaws.com","metadata.google.internal")
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","curl.exe","python.exe","cmd.exe")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Enforce strong identity governance and access control policies  
* Monitor synchronization and federation configurations  
* Implement multi-factor authentication for cloud and hybrid accounts  
* Conduct regular audits of cloud access permissions

## Incident Response

* Identify compromised cloud or hybrid accounts  
* Revoke unauthorized access tokens and credentials  
* Review cloud activity logs and synchronization history  
* Assess impact on connected infrastructure

## Chain Linking

`EXPANSION → Foothold Widened → EXTRACTION`

**Enables next:**

- [HTTP / HTTPS Data Exfiltration](../ext/MC-EXT-01.md) (`EXT-01`)
- [Cloud Storage Abuse](../ext/MC-EXT-03.md) (`EXT-03`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Directory Services Targeting](../exp/MC-EXP-09.md) | [HTTP / HTTPS Data Exfiltration →](../ext/MC-EXT-01.md)
