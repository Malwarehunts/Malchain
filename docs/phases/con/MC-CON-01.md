# CON-01 · Obfuscation & Packing

**Phase:** [Concealment](../con.md) · Defense Evasion  |  **Detections:** KQL · YARA

[← Back to Concealment](../con.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Obfuscation & Packing refers to the transformation of attacker-controlled code into formats that conceal functionality and evade detection mechanisms within a target environment. This includes encoding, encrypting, compressing, or restructuring executable content so that its true behavior is hidden until runtime. Within MalChain, this capability begins once code is modified to obscure analysis or signature recognition while preserving operational functionality. Attackers exploit implicit trust in executable files and runtime environments to deploy concealed logic that bypasses traditional inspection controls. Software complexity and automated execution processes often allow obfuscated code to operate without immediate scrutiny. Trust abuse may involve disguised binaries, encoded scripts, or compressed payloads presented as legitimate software components. Common evasion methods include:

* Encrypting or encoding executable content  
* Compressing payloads using packer utilities  
* Renaming or restructuring code to hide functionality  
* Embedding encrypted payloads within legitimate files  
* Dynamically unpacking code during execution  

Real world usage includes:

* Malware campaigns designed to evade signature-based detection  
* Delivery of ransomware payloads in concealed formats  
* Advanced persistent threat operations using custom packers  
* Automated malware distribution using obfuscated scripts

## Detection Guidance

Detection relies on monitoring file structure anomalies, runtime behavior, and execution patterns associated with transformed code. Contextual correlation between file characteristics and execution activity is essential to reduce false positives.

* Monitor files exhibiting abnormal entropy or compression patterns  
* Detect execution of binaries that unpack code at runtime  
* Correlate file creation with unexpected execution behavior  
* Alert on files with mismatched file structure or metadata  
* Identify rare or unknown packer signatures

## KQL Detection Concepts

* File creation events involving compressed or encoded executables  
* Process execution associated with runtime unpacking behavior  
* Files exhibiting abnormal entropy or structure characteristics

## YARA Detection Concepts

* Known packer signatures or encoded payload indicators  
* Executables containing embedded encrypted sections  
* Code patterns associated with runtime unpacking routines

## KQL Detection Rule

```kql
// Obfuscation & Packing: newly written PE with very high entropy sections
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".exe" or FileName endswith ".dll"
| where FolderPath has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName
// Pivot SHA256 into a sandbox/entropy source; alert on packer indicators (UPX/MPRESS/Themida)
```

## YARA Detection Rule

```yara
rule MC_CON_01_Packed_Executable
{
    meta:
        author = "MalChain"
        technique = "MC-CON-01 Obfuscation & Packing"
        description = "Common runtime packer section names in a PE"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mpress = ".MPRESS1" ascii
        $aspack = ".aspack" ascii
        $themida = "Themida" ascii nocase
        $petite = ".petite" ascii
    condition:
        uint16(0) == 0x5A4D and 1 of them
}
```

## Mitigation

* Implement advanced malware detection and behavioral analysis  
* Enforce file integrity validation and reputation controls  
* Monitor execution of unknown or newly created binaries  
* Restrict execution from untrusted file sources

## Incident Response

* Identify files exhibiting obfuscation or packing characteristics  
* Isolate affected systems from the network  
* Analyze unpacked payload behavior in controlled environments  
* Review execution timelines and file origin

## Chain Linking

`CONCEALMENT → Visibility Degraded → reinforced within CONCEALMENT`

**Enables next:**

- [Fileless Malware Execution](../con/MC-CON-02.md) (`CON-02`)
- [Process Injection](../con/MC-CON-06.md) (`CON-06`)
- [Polymorphism & Metamorphism](../con/MC-CON-07.md) (`CON-07`)

---

[← Boot & Pre-OS Persistence](../anc/MC-ANC-08.md) | [Fileless Malware Execution →](../con/MC-CON-02.md)
