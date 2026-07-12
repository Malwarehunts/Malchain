# CON-09 · Living-off-the-Land for Evasion

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Living-off-the-Land for Evasion refers to the use of legitimate system tools, utilities, and built-in administrative functions to perform attacker-controlled actions while avoiding detection. This includes leveraging trusted binaries, scripting environments, and native operating system components to execute commands without introducing external malware files. Within MalChain, this capability begins once attacker activity is conducted using authorized tools in a manner that blends with routine system operations. Attackers exploit implicit trust in standard administrative utilities and system maintenance processes to carry out actions that appear legitimate. Routine reliance on built-in tools and automation often allows misuse to go unnoticed within normal operational workflows. Trust abuse may involve executing commands through trusted utilities, chaining legitimate tools to perform malicious actions, or using system management features presented as routine maintenance. Common evasion methods include:

* Executing commands using trusted system utilities  
* Leveraging administrative scripting tools for unauthorized actions  
* Using built-in system binaries to perform malicious tasks  
* Automating actions through legitimate maintenance tools  
* Combining multiple trusted utilities to execute complex operations  

Real world usage includes:

* Intrusion campaigns using native system tools to avoid detection  
* Ransomware staging operations leveraging built-in utilities  
* Insider threat activities conducted using legitimate administrative tools  
* Persistent threats minimizing forensic artifacts through native execution

## Detection Guidance

Detection relies on monitoring usage patterns of trusted utilities, command execution behavior, and system activity associated with administrative tools. Contextual correlation between legitimate tool usage and abnormal system behavior is essential to reduce false positives.

* Monitor execution of administrative tools outside normal operational patterns  
* Detect unusual command-line arguments associated with trusted utilities  
* Correlate tool usage with unexpected system changes  
* Alert on repetitive execution of system utilities across multiple systems  
* Identify rare or unauthorized combinations of legitimate tools

## KQL Detection Concepts

* Process execution events involving trusted system binaries used in unusual contexts  
* Command-line activity indicating misuse of administrative utilities  
* Repeated execution patterns involving native system tools

## YARA Detection Concepts

* Scripts or binaries invoking trusted system utilities in suspicious sequences  
* Code patterns chaining legitimate commands for unauthorized actions  
* Executable components designed to automate misuse of built-in tools

## KQL Detection Rule

```kql
// Living-off-the-Land for Evasion: proxy execution via trusted binaries
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("regsvr32.exe","rundll32.exe","mshta.exe","installutil.exe","msbuild.exe","certutil.exe","regasm.exe","regsvcs.exe")
| where ProcessCommandLine has_any ("http","scrobj","javascript:","-decode","-urlcache","/i:","AppData","Temp")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_CON_09_LOLBin_Proxy_Execution
{
    meta:
        author = "MalChain"
        technique = "MC-CON-09 Living-off-the-Land for Evasion"
        description = "LOLBin proxy-execution command patterns"
    strings:
        $a = "regsvr32" ascii nocase
        $s = "scrobj.dll" ascii nocase
        $b = "mshta" ascii nocase
        $j = "javascript:" ascii nocase
        $c = "certutil" ascii nocase
        $u = "-urlcache" ascii nocase
    condition:
        ($a and $s) or ($b and $j) or ($c and $u)
}
```

## Mitigation

* Restrict administrative tool usage to authorized personnel  
* Monitor command-line activity and system utility execution  
* Implement application control and least-privilege access policies  
* Maintain visibility into administrative automation workflows

## Incident Response

* Identify systems where trusted tools were misused  
* Review command execution history and associated system changes  
* Isolate affected systems if malicious activity is confirmed  
* Analyze operational timelines for abnormal tool usage

## Chain Linking

`CONCEALMENT → Visibility Degraded → EXTRACTION`

**Enables next:**

- [Anti-Forensics & Cleanup](../con/MC-CON-10.md) (`CON-10`)
- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Log & Artifact Manipulation](../con/MC-CON-08.md) | [Anti-Forensics & Cleanup →](../con/MC-CON-10.md)
