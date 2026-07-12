# EXP-06 · Worm-like Self-Propagation

**Phase:** [Expansion](../exp.md) · Lateral Movement  |  **Detections:** KQL · YARA

[← Back to Expansion](../exp.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Worm-like Self-Propagation refers to the automated spread of attacker-controlled code across multiple systems within a target environment without requiring direct user interaction. This includes the use of scripts, network scanning routines, or replication mechanisms that identify new targets and deploy execution logic automatically. Within MalChain, this capability begins once malicious logic independently discovers additional systems and initiates propagation actions. Attackers exploit implicit trust in network connectivity and system communication protocols to expand operational reach rapidly. Routine reliance on interconnected infrastructure and automated communication often allows propagation activity to occur before defensive controls respond. Trust abuse may involve self-replicating scripts, automated deployment routines, or scanning tools presented as legitimate system operations. Common propagation methods include:

* Automatically scanning networks for accessible systems  
* Replicating executable files across multiple hosts  
* Deploying scripts that initiate remote execution  
* Leveraging network vulnerabilities for automated spread  
* Using scheduled tasks or services to continue propagation  

Real world usage includes:

* Rapid ransomware outbreaks spreading across enterprise networks  
* Self-propagating malware targeting vulnerable systems  
* Large-scale intrusion campaigns expanding access automatically  
* Persistent threats using automated replication to maintain presence

## Detection Guidance

Detection relies on monitoring network scanning behavior, repeated connection attempts, and execution patterns associated with automated propagation. Contextual correlation between system activity and network behavior is essential to reduce false positives.

* Monitor repeated connection attempts to multiple systems  
* Detect automated execution of similar files across hosts  
* Correlate network scanning activity with system access attempts  
* Alert on rapid file distribution or execution patterns  
* Identify rare or unauthorized replication behavior

## KQL Detection Concepts

* Network connection events indicating automated scanning behavior  
* Repeated execution of identical processes across multiple systems  
* Rapid authentication attempts targeting multiple hosts

## YARA Detection Concepts

* Scripts or binaries containing self-replication logic  
* Code patterns associated with automated network scanning  
* Executable components designed for autonomous propagation

## KQL Detection Rule

```kql
// Worm-like Self-Propagation: one process writing identical binary to many hosts/shares
DeviceFileEvents
| where Timestamp > ago(2d)
| where ActionType == "FileCreated" and (FileName endswith ".exe" or FileName endswith ".dll")
| summarize Targets=dcount(DeviceName), Paths=dcount(FolderPath) by SHA256, InitiatingProcessFileName
| where Targets > 5 or Paths > 20
| project SHA256, InitiatingProcessFileName, Targets, Paths
```

## YARA Detection Rule

```yara
rule MC_EXP_06_Worm_SelfPropagation
{
    meta:
        author = "MalChain"
        technique = "MC-EXP-06 Worm-like Self-Propagation"
        description = "Self-copy to network shares / removable drives via enumeration"
    strings:
        $a1 = "WNetAddConnection2" ascii
        $a2 = "GetLogicalDrives" ascii
        $a3 = "CopyFile" ascii
        $s1 = "\\ADMIN$" ascii nocase
        $s2 = "\\C$" ascii nocase
        $s3 = "autorun.inf" ascii nocase
    condition:
        uint16(0) == 0x5A4D and 1 of ($a*) and 1 of ($s*)
}
```

## Mitigation

* Implement network segmentation and access control policies  
* Monitor network traffic for scanning and replication activity  
* Enforce vulnerability management and patching procedures  
* Restrict execution privileges for automated deployment tools

## Incident Response

* Identify systems involved in propagation activity  
* Isolate affected hosts from the network  
* Remove self-propagating components from compromised systems  
* Review network logs and propagation timelines

## Chain Linking

`EXPANSION → Foothold Widened → reinforced within EXPANSION`

**Enables next:**

- [Privilege Escalation Across Hosts](../exp/MC-EXP-07.md) (`EXP-07`)
- [Identity & Trust Relationship Abuse](../exp/MC-EXP-08.md) (`EXP-08`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Network Share Propagation](../exp/MC-EXP-05.md) | [Privilege Escalation Across Hosts →](../exp/MC-EXP-07.md)
