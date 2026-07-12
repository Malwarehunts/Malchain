# EXP-09 · Directory Services Targeting

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL · YARA

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Directory Services Targeting refers to the deliberate interaction with centralized identity and resource management systems to discover, manipulate, or control user accounts, permissions, and organizational structures within a target environment. This includes querying directory databases, modifying group memberships, or altering authentication policies to expand access and maintain operational control. Within MalChain, this capability begins once attacker-controlled activity directly interacts with directory infrastructure to influence identity or authorization mechanisms. Attackers exploit implicit trust in centralized directory services and administrative management processes to gain visibility into the environment and escalate privileges. Routine reliance on directory synchronization and automated account management often allows unauthorized changes to occur without immediate detection. Trust abuse may involve modifying user privileges, creating hidden accounts, or altering directory configurations presented as legitimate administrative actions. Common targeting methods include:

* Querying directory services for user and group information  
* Modifying group membership or role assignments  
* Creating or enabling privileged accounts  
* Changing authentication or access control policies  
* Synchronizing directory data across multiple systems  

Real world usage includes:

* Enterprise intrusion campaigns targeting centralized identity infrastructure  
* Ransomware operators gaining domain-wide administrative control  
* Insider threat scenarios involving unauthorized account modifications  
* Persistent threats maintaining access through directory manipulation

## Detection Guidance

Detection relies on monitoring directory service activity, account management events, and authorization changes associated with identity infrastructure. Contextual correlation between directory modifications and system behavior is essential to reduce false positives.

* Monitor creation or modification of user and group accounts  
* Detect changes to directory permissions or access policies  
* Correlate directory queries with unusual authentication activity  
* Alert on creation of privileged or hidden accounts  
* Identify rare or unauthorized directory configuration changes

## KQL Detection Concepts

* Account creation or privilege modification events in directory services  
* Directory queries indicating enumeration of users or groups  
* Authentication policy changes affecting access control

## YARA Detection Concepts

* Scripts or binaries interacting with directory management interfaces  
* Code patterns associated with account enumeration or modification  
* Executable components modifying identity or permission settings

## KQL Detection Rule

```kql
// Directory Services Targeting: DCSync / mass LDAP enumeration
union
(DeviceProcessEvents
 | where ProcessCommandLine has_any ("lsadump::dcsync","dcsync","GetNCChanges","Get-ADReplAccount")
 | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine),
(IdentityDirectoryEvents
 | where ActionType == "Directory Services replication"
 | project Timestamp, DeviceName=TargetDeviceName, AccountName=AccountUpn, ActionType)
```

## YARA Detection Rule

```yara
rule MC_EXP_09_DCSync_Directory_Attack
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-09 Directory Services Targeting"
        description = "DCSync / directory replication abuse artifacts"
    strings:
        $a = "lsadump::dcsync" ascii nocase
        $b = "GetNCChanges" ascii
        $c = "DsGetNCChanges" ascii
        $d = "Get-ADReplAccount" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Restrict administrative access to directory services  
* Implement role-based access control and approval workflows  
* Monitor directory changes and account management activity  
* Conduct regular audits of identity and permission configurations

## Incident Response

* Identify unauthorized directory modifications or account changes  
* Disable or remove compromised accounts  
* Review directory logs and access history  
* Assess impact on identity and authorization infrastructure

## Chain Linking

`EXPANSION → Foothold Widened → EXTRACTION`

**Enables next:**

- [Cloud & Hybrid Lateral Movement](../exp/MC-EXP-10.md) (`EXP-10`)
- [Messaging and Social Platform Channels](../ext/MC-EXT-04.md) (`EXT-04`)
- [Encrypted Command-and-Control Channels](../ext/MC-EXT-07.md) (`EXT-07`)

---

[← Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) | [Cloud & Hybrid Lateral Movement →](../exp/MC-EXP-10.md)
