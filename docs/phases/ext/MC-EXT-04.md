# EXT-04 · Messaging and Social Platform Channels

**Phase:** [Extraction](../ext.md) · Exfiltration & C2  |  **Detections:** KQL · YARA

[← Back to Extraction](../ext.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Messaging and Social Platform Channels refers to the use of communication platforms such as chat applications, collaboration tools, and social media services to transmit attacker-controlled data or commands outside a target environment. This includes sending files, messages, or encoded instructions through widely used communication channels that appear consistent with routine user interaction. Within MalChain, this capability begins once sensitive information or operational commands are successfully transmitted through messaging or social platforms under attacker control. Attackers exploit implicit trust in legitimate communication services and encrypted messaging infrastructure to move data while avoiding traditional network monitoring controls. Routine reliance on collaboration and communication tools often allows unauthorized data transfer to occur without immediate detection. Trust abuse may involve creating fake accounts, sharing files through private messages, or embedding data within normal communication traffic presented as legitimate conversation activity. Common communication methods include:

* Sending files through messaging or chat applications  
* Sharing information through social media platforms  
* Transmitting encoded data within message content  
* Using collaboration tools to exchange sensitive files  
* Leveraging group messaging to distribute information  

Real world usage includes:

* Data exfiltration campaigns using communication platforms  
* Insider threat scenarios involving unauthorized file sharing  
* Persistent threats maintaining covert communication channels  
* Ransomware operators coordinating activity through messaging services

## Detection Guidance

Detection relies on monitoring communication activity, file sharing behavior, and network usage patterns associated with messaging platforms. Contextual correlation between communication activity and data access behavior is essential to reduce false positives.

* Monitor file transfers through messaging or collaboration tools  
* Detect communication with unauthorized external accounts  
* Correlate messaging activity with sensitive data access events  
* Alert on large or unusual file sharing activity  
* Identify rare or unauthorized communication patterns

## KQL Detection Concepts

* Network events indicating communication with messaging platforms  
* File transfer activity associated with collaboration applications  
* Authentication events involving new or unfamiliar communication accounts

## YARA Detection Concepts

* Scripts or binaries interacting with messaging or social platform APIs  
* Code patterns associated with automated message transmission  
* Executable components sending files through communication services

## KQL Detection Rule

```kql
// Messaging/Social Channels: exfil via Telegram/Discord/webhook APIs
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("api.telegram.org","discord.com/api/webhooks","discordapp.com/api/webhooks","hooks.slack.com","pastebin.com")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","teams.exe","slack.exe","discord.exe")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## YARA Detection Rule

```yara
rule MC_EXT_04_Messaging_Channel_Exfil
{
    meta:
        author = "MalChain"
        technique = "MC-EXT-04 Messaging and Social Platform Channels"
        description = "Hardcoded Telegram/Discord webhook exfil endpoints"
    strings:
        $a = "api.telegram.org/bot" ascii nocase
        $b = "discord.com/api/webhooks" ascii nocase
        $c = "discordapp.com/api/webhooks" ascii nocase
        $d = "hooks.slack.com/services" ascii nocase
    condition:
        1 of them
}
```

## Mitigation

* Implement communication platform usage policies and monitoring  
* Restrict file sharing permissions within messaging applications  
* Enforce data loss prevention and content inspection controls  
* Monitor communication activity for unauthorized transfers

## Incident Response

* Identify accounts involved in unauthorized communication activity  
* Block access to compromised messaging or social platform accounts  
* Analyze transferred files and associated communication logs  
* Review user activity and communication timelines

## Chain Linking

`EXTRACTION → Impact Realized → reinforced within EXTRACTION`

**Enables next:**

- [FTP / SFTP / FTPS Transfer](../ext/MC-EXT-05.md) (`EXT-05`)
- [Tor / Proxy / VPN Anonymization Channels](../ext/MC-EXT-06.md) (`EXT-06`)
- [Multi-Channel Redundant Exfiltration](../ext/MC-EXT-10.md) (`EXT-10`)

---

[← Cloud Storage Abuse](../ext/MC-EXT-03.md) | [FTP / SFTP / FTPS Transfer →](../ext/MC-EXT-05.md)
