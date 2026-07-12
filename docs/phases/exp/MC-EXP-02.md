# EXP-02 · Credential Reuse & Relay

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Credential Reuse & Relay refers to the use of previously obtained authentication material to access additional systems or services within a target environment without directly exposing the original credentials. This includes reusing valid passwords, session tokens, or authentication responses to authenticate across multiple systems. Within MalChain, this capability begins once attacker-controlled activity leverages existing credentials to establish authenticated access beyond the initial system. Attackers exploit implicit trust in identity verification systems and authentication workflows to move laterally while appearing as legitimate users. Routine reliance on shared credentials and persistent authentication sessions often allows repeated access attempts to occur without immediate detection. Trust abuse may involve reusing cached credentials, relaying authentication requests between systems, or leveraging stored session tokens presented as legitimate user activity. Common movement methods include:

* Reusing valid credentials across multiple systems  
* Relaying authentication requests between hosts  
* Leveraging cached or stored credentials for access  
* Using active user sessions to authenticate to remote services  
* Replaying authentication tokens or responses  

Real world usage includes:

* Enterprise intrusion campaigns expanding access using compromised accounts  
* Ransomware operators leveraging stolen credentials to spread across networks  
* Insider threat scenarios involving unauthorized credential sharing  
* Persistent threats maintaining access through repeated authentication

## Detection Guidance

Detection relies on monitoring authentication patterns, session activity, and system access behavior associated with credential usage. Contextual correlation between login events and system activity is essential to reduce false positives.

* Monitor authentication attempts across multiple systems  
* Detect repeated login activity using the same credentials  
* Correlate session usage with unexpected network access  
* Alert on authentication requests originating from unusual locations  
* Identify rare or unauthorized credential usage patterns

## KQL Detection Concepts

* Authentication events involving the same credentials across multiple hosts  
* Session activity occurring outside normal operational patterns  
* Repeated login attempts within short time intervals

## YARA Detection Concepts

* Scripts or binaries interacting with authentication mechanisms  
* Code patterns automating credential usage or relay operations  
* Executable components designed to capture or reuse authentication data

## KQL Detection Rule

```kql
// Credential Reuse & Relay: same account authenticating to many hosts quickly
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess" and LogonType in ("Network","RemoteInteractive")
| summarize Hosts=dcount(DeviceName), HostSet=make_set(DeviceName,20) by AccountName, bin(Timestamp, 15m)
| where Hosts >= 5
| project Timestamp, AccountName, Hosts, HostSet
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

* Enforce strong authentication and credential management policies  
* Implement multi-factor authentication for system access  
* Monitor credential usage and session behavior continuously  
* Restrict credential sharing and enforce least-privilege access

## Incident Response

* Identify compromised credentials and affected systems  
* Reset passwords and revoke active sessions  
* Review authentication logs and access history  
* Monitor for continued unauthorized credential usage

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Pass-the-Hash / Pass-the-Ticket](../exp/MC-EXP-03.md) (`EXP-03`)
- [Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) (`EXP-08`)
- [DNS Tunneling](../ext/MC-EXT-02.md) (`EXT-02`)

---

[← Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) | [Pass-the-Hash / Pass-the-Ticket →](../exp/MC-EXP-03.md)
