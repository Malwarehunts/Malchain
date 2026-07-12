# ACT-06 · Browser Extension Execution

**Phase:** [Activation](../act.md) · Execution  |  **Detections:** KQL · YARA

[← Back to Activation](../act.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Browser Extension Execution refers to the use of browser add-ons or plugins to execute attacker-controlled logic within a target environment. This includes installing, modifying, or abusing browser extensions to run scripts, intercept data, or manipulate web sessions. Within MalChain, this capability begins once an extension is installed or activated and gains execution privileges within the browser runtime environment. Attackers exploit implicit trust in browser ecosystems and extension functionality to execute code while blending into routine user activity. Convenience, productivity features, and automated browser behavior often allow extensions to operate with broad permissions and minimal oversight. Trust abuse may involve extensions disguised as productivity tools, security utilities, or required application components. Common execution methods include:

* Installing malicious browser extensions from official or third-party stores  
* Modifying existing extensions to include hidden scripts  
* Injecting code into browser sessions through extension APIs  
* Executing background scripts triggered by browsing activity  
* Using extensions to interact with web content or user credentials  

Real world usage includes:

* Credential theft and session hijacking campaigns  
* Browser-based spyware and surveillance operations  
* Ad fraud and web traffic manipulation schemes  
* Initial access or persistence in enterprise environments

## Detection Guidance

Detection relies on monitoring extension installation events, permission changes, and runtime behavior associated with browser processes. Contextual correlation between extension activity and user behavior is essential to reduce false positives.

* Monitor installation of new browser extensions  
* Detect changes to extension permissions or configuration settings  
* Correlate extension activity with unusual browser behavior  
* Alert on extensions requesting excessive or uncommon privileges  
* Identify extensions installed outside approved distribution channels

## KQL Detection Concepts

* Browser extension installation or modification events  
* Browser processes loading newly installed or unsigned extensions  
* Extension activity associated with credential access or data transfer

## YARA Detection Concepts

* Extension packages containing suspicious script logic  
* Files with embedded credential interception or data collection routines  
* Code patterns interacting with browser APIs for unauthorized actions

## KQL Detection Rule

```kql
// Browser Extension Execution: new/modified extension manifest with broad permissions
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has_any (@"\Extensions\", @"\Extension Settings\")
| where FileName in~ ("manifest.json","background.js","content.js")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, SHA256
```

## YARA Detection Rule

```yara
rule MC_ACT_06_Malicious_Browser_Extension
{
    meta:
        author = "MalChain"
        technique = "MC-ACT-06 Browser Extension Execution"
        description = "Extension manifest requesting broad permissions + remote code"
    strings:
        $m = "manifest_version" ascii
        $p1 = "\"<all_urls>\"" ascii
        $p2 = "webRequest" ascii
        $p3 = "tabs" ascii
        $c1 = "eval(" ascii
        $c2 = "chrome.runtime.onMessage" ascii
    condition:
        $m and 1 of ($p*) and 1 of ($c*)
}
```

## Mitigation

* Restrict extension installation to approved sources  
* Enforce extension permission controls and review processes  
* Monitor browser configuration and extension usage  
* Implement security policies governing browser add-ons

## Incident Response

* Identify installed or modified browser extensions  
* Remove unauthorized or suspicious extensions  
* Analyze extension code and associated activity  
* Review browser logs and user session behavior

## Chain Linking

`ACTIVATION → Code Executing → EXTRACTION`

**Enables next:**

- [Boot / Firmware Execution](../act/MC-ACT-07.md) (`ACT-07`)
- [Browser-Based Persistence](../anc/MC-ANC-05.md) (`ANC-05`)
- [Messaging and Social Platform Channels](../ext/MC-EXT-04.md) (`EXT-04`)

---

[← WMI-Based Execution](../act/MC-ACT-05.md) | [Boot / Firmware Execution →](../act/MC-ACT-07.md)
