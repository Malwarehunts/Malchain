# ING-05 · Malicious or Compromised USB Devices

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL · YARA

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Malicious or Compromised USB Devices refer to physical peripherals that present themselves as legitimate hardware (storage, keyboard, network adapter) while executing attacker-controlled logic. These devices may contain modified firmware or embedded microcontrollers. Within MalChain, this capability ends once device interaction results in system-level access or execution opportunity. Attackers exploit:
	
*   Implicit trust in USB devices
*   Automatic driver installation
*   Human curiosity and convenience
*   Limited firmware inspection
  
Device identity is assumed rather than verified. Observed attack patterns include:

*   HID emulation (keyboard injection)
*   USB network adapter spoofing
*   Firmware-flashed storage devices
*   Composite device masquerading
  
The real world usage includes:

*   Targeted espionage operations
*   Red team simulation frameworks
*   Air-gapped network attacks
*   Physical intrusion campaigns

## Detection Guidance

Detection focuses on device enumeration events, driver installation logs, and abnormal behavior following peripheral insertion. Visibility into USB class and firmware behavior is critical.

*   Monitor new USB device enumeration
*   Detect HID devices attached unexpectedly
*   Alert on USB-triggered command execution
*   Identify new network interfaces via USB
*   Correlate device insertion with execution events

## KQL Detection Concepts

*   USB device insertion events
*   New HID or network device detection
*   Process execution shortly after USB insertion

## YARA Detection Concepts

*   HID attack scripts
*   Embedded payload logic
*   Peripheral-triggered loaders

## KQL Detection Rule

```kql
// Malicious USB: new PnP HID / storage device followed by rapid process execution
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("PnpDeviceConnected","UsbDriveMounted")
| project ConnectTime=Timestamp, DeviceName, AdditionalFields
| join kind=inner (
    DeviceProcessEvents
    | where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe")
    | project ExecTime=Timestamp, DeviceName, FileName, ProcessCommandLine
) on DeviceName
| where ExecTime between (ConnectTime .. (ConnectTime + 2m))
```

## YARA Detection Rule

```yara
rule MC_ING_05_BadUSB_HID_Payload
{
    meta:
        author = "MalChain"
        technique = "MC-ING-05 Malicious or Compromised USB Devices"
        description = "Rubber Ducky / BadUSB keystroke-injection script artifacts"
    strings:
        $d1 = "DELAY " ascii
        $d2 = "STRING " ascii
        $d3 = "GUI r" ascii
        $d4 = "ENTER" ascii
        $d5 = "duckyscript" ascii nocase
    condition:
        $d5 or (3 of ($d1,$d2,$d3,$d4))
}
```

## Mitigation

*   Restrict USB device classes
*   Disable automatic driver installation
*   Enforce device control policies
*   Use hardware whitelisting

## Incident Response

*   Physically secure and isolate device
*   Identify injected commands or payloads
*   Review system changes post-insertion
*   Hunt for follow-on execution

## Chain Linking

`INGRESS → Peripheral Trust → Automatic Device Execution → ACTIVATION`

**Enables next:**

- [Script-Based Execution](../act/MC-ACT-02.md) (`ACT-02`)
- [User-Executed Files](../act/MC-ACT-01.md) (`ACT-01`)
- [Credential Abuse](../ing/MC-ING-04.md) (`ING-04`)

---

[← Credential Abuse](../ing/MC-ING-04.md) | [Watering Hole Attacks →](../ing/MC-ING-06.md)
