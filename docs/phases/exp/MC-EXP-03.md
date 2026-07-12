# EXP-03 · Pass-the-Hash / Pass-the-Ticket

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL · YARA

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Pass-the-Hash / Pass-the-Ticket refers to the use of captured authentication artifacts to gain access to systems without knowing the original plaintext credentials. This includes leveraging hashed passwords, authentication tickets, or session tokens to authenticate across network services. Within MalChain, this capability begins once attacker-controlled activity successfully uses authentication material to access additional systems or services. Attackers exploit implicit trust in authentication protocols and credential validation mechanisms to establish access while avoiding direct credential exposure. Routine reliance on centralized authentication services and session-based access often allows repeated authentication attempts to occur without immediate detection. Trust abuse may involve reusing stored authentication hashes, injecting ticket-based credentials into active sessions, or presenting forged authentication tokens as legitimate user activity. Common movement methods include:

* Using captured password hashes to authenticate to remote systems  
* Injecting authentication tickets into existing sessions  
* Reusing stored credential artifacts for system access  
* Leveraging authentication responses to bypass password verification  
* Accessing network services using intercepted authentication data  

Real world usage includes:

* Enterprise intrusion campaigns using stolen authentication artifacts  
* Ransomware operators spreading across networks using credential hashes  
* Targeted attacks leveraging centralized authentication infrastructure  
* Persistent threats maintaining access through ticket-based authentication

## Detection Guidance

Detection relies on monitoring authentication behavior, session activity, and system access patterns associated with credential artifacts. Contextual correlation between login events and network access behavior is essential to reduce false positives.

* Monitor authentication attempts using credential artifacts  
* Detect login activity inconsistent with known user behavior  
* Correlate session activity with unusual network access patterns  
* Alert on repeated authentication attempts across multiple systems  
* Identify rare or unauthorized use of authentication tickets

## KQL Detection Concepts

* Authentication events involving non-interactive login methods  
* Session activity indicating reuse of credential artifacts  
* Access attempts to multiple systems using identical authentication identifiers

## YARA Detection Concepts

* Scripts or binaries interacting with authentication protocols  
* Code patterns associated with credential injection or ticket manipulation  
* Executable components designed to use captured authentication artifacts

## KQL Detection Rule

```kql
// Pass-the-Hash / Pass-the-Ticket: NTLM/Kerberos logon anomalies from lsass access
DeviceLogonEvents
| where Timestamp > ago(3d)
| where LogonType == "Network" and ActionType == "LogonSuccess"
| where isempty(RemoteIP) == false
| join kind=inner (DeviceEvents | where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe" | project DeviceName, Timestamp) on DeviceName
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

## YARA Detection Rule

```yara
rule MC_EXP_03_Credential_Ticket_Tooling
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-03 Pass-the-Hash / Pass-the-Ticket"
        description = "Mimikatz/Rubeus PtH/PtT command artifacts"
    strings:
        $a = "sekurlsa::pth" ascii nocase
        $b = "sekurlsa::logonpasswords" ascii nocase
        $c = "kerberos::ptt" ascii nocase
        $d = "asktgt" ascii nocase
        $e = "Rubeus" ascii
    condition:
        1 of them
}
```

## Mitigation

* Implement credential protection and secure authentication mechanisms  
* Enforce multi-factor authentication for privileged access  
* Monitor authentication and session activity continuously  
* Restrict access to credential storage and authentication services

## Incident Response

* Identify systems accessed using compromised authentication artifacts  
* Revoke active authentication sessions and reset credentials  
* Review authentication logs and access history  
* Monitor network activity for continued unauthorized access

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Remote Service & Protocol Abuse](../exp/MC-EXP-04.md) (`EXP-04`)
- [Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) (`EXP-08`)
- [Encrypted Command-and-Control Channels](../ext/MC-EXT-07.md) (`EXT-07`)

---

[← Credential Reuse & Relay](../exp/MC-EXP-02.md) | [Remote Service & Protocol Abuse →](../exp/MC-EXP-04.md)
