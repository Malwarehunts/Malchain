# EXP-08 · Identity & Trust Relationship Abuse

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL · YARA

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Identity & Trust Relationship Abuse refers to the exploitation of established trust relationships between users, systems, domains, or services to gain unauthorized access within a target environment. This includes leveraging delegated permissions, federated authentication, or inter-system trust mechanisms to access resources beyond the originally compromised scope. Within MalChain, this capability begins once attacker-controlled activity successfully uses a trusted relationship to bypass standard access restrictions and extend operational control. Attackers exploit implicit trust in identity federation, domain relationships, and shared authentication frameworks to move across organizational boundaries without triggering traditional security alerts. Routine reliance on interconnected systems and delegated administration often allows misuse of trust relationships to occur without immediate detection. Trust abuse may involve misusing service accounts, exploiting cross-domain trust configurations, or leveraging synchronization mechanisms presented as legitimate operational behavior. Common abuse methods include:

* Leveraging delegated permissions to access additional systems  
* Exploiting trust relationships between domains or environments  
* Using federated authentication to access remote resources  
* Abusing service accounts shared across systems  
* Synchronizing credentials across trusted infrastructure  

Real world usage includes:

* Enterprise intrusion campaigns exploiting domain trust relationships  
* Cloud and hybrid environment compromises leveraging identity federation  
* Ransomware operators expanding control through shared administrative accounts  
* Persistent threats moving across organizational boundaries

## Detection Guidance

Detection relies on monitoring authentication flows, trust relationship activity, and access patterns associated with delegated permissions. Contextual correlation between identity usage and resource access is essential to reduce false positives.

* Monitor authentication activity across trusted domains or systems  
* Detect access to resources through delegated permissions  
* Correlate identity synchronization events with unusual access behavior  
* Alert on unexpected cross-domain authentication attempts  
* Identify rare or unauthorized use of shared service accounts

## KQL Detection Concepts

* Authentication events involving cross-domain or federated access  
* Access patterns indicating use of delegated permissions  
* Synchronization activity between trusted identity systems

## YARA Detection Concepts

* Scripts or binaries interacting with identity synchronization services  
* Code patterns associated with credential federation or trust configuration  
* Executable components accessing remote resources through trusted relationships

## KQL Detection Rule

```kql
// Identity & Trust Relationship Abuse: golden/silver ticket & delegation abuse recon
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("kerberos::golden","kerberos::ptt","Add-KrbtgtKey","asktgt","s4u","/impersonateuser","Rubeus")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_EXP_08_Kerberos_Trust_Abuse
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-08 Identity & Trust Relationship Abuse"
        description = "Golden/silver ticket and delegation abuse artifacts"
    strings:
        $a = "kerberos::golden" ascii nocase
        $b = "kerberos::silver" ascii nocase
        $c = "/krbtgt" ascii nocase
        $d = "s4u" ascii nocase
        $e = "/impersonateuser" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Enforce strict control over delegated permissions and service accounts  
* Monitor trust relationships between systems and domains  
* Implement conditional access and identity governance policies  
* Conduct regular audits of identity federation and synchronization settings

## Incident Response

* Identify compromised trust relationships and affected systems  
* Revoke unauthorized delegated permissions  
* Review authentication and synchronization logs  
* Assess scope of access across trusted environments

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Directory Services Targeting](../exp/MC-EXP-09.md) (`EXP-09`)
- [Cloud & Hybrid Lateral Movement](../exp/MC-EXP-10.md) (`EXP-10`)
- [HTTP / HTTPS Data Exfiltration](../ext/MC-EXT-01.md) (`EXT-01`)

---

[← Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) | [Directory Services Targeting →](../exp/MC-EXP-09.md)
