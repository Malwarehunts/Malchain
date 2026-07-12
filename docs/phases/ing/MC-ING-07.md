# ING-07 · External Remote Services

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

External Remote Services ingress occurs when attackers gain access through internet-facing services that are designed for legitimate remote connectivity. These include VPNs, RDP, VDI platforms, SSH, cloud admin portals, and SaaS applications. Within MalChain, this capability ends once authenticated or network-level access is established. Attackers exploit trust in:
	
*   Remote access infrastructure
*   Cloud identity providers
*   MFA fatigue or misconfiguration
*   Legacy authentication protocols
  
Observed abuse patterns include:

*   VPN credential compromise
*   RDP brute force or reuse
*   SaaS account takeover
*   API token misuse
  
The real world usage includes:

*   Ransomware intrusions
*   Cloud account takeover campaigns
*   Initial access broker operations

## Detection Guidance

Detection relies on remote access logs, identity telemetry, and correlation with endpoint execution events.

*   Monitor anomalous VPN logins
*   Detect RDP access from rare locations
*   Alert on MFA fatigue patterns
*   Monitor SaaS admin activity
*   Correlate remote login with execution

## KQL Detection Concepts

*   Successful VPN login followed by process creation
*   RDP session start preceding execution events
*   Cloud admin actions outside baseline behavior

## YARA Detection Concepts

*   Remote execution stagers
*   Credential harvesting logic
*   Cloud abuse tooling

## KQL Detection Rule

```kql
// External Remote Services: external RDP/VPN success followed by admin tool use
DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType in ("RemoteInteractive","Network") and ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

*   Enforce MFA everywhere
*   Restrict exposed services
*   Monitor remote access posture
*   Implement conditional access

## Incident Response

*   Revoke compromised sessions
*   Reset affected credentials
*   Review accessed systems
*   Hunt for persistence and lateral movement

## Chain Linking

`INGRESS → Authenticated Remote Access → ACTIVATION`

**Enables next:**

- [Service-Based Execution](../act/MC-ACT-03.md) (`ACT-03`)
- [Credential Abuse](../ing/MC-ING-04.md) (`ING-04`)
- [Living-off-the-Land Lateral Movement](../exp/MC-EXP-01.md) (`EXP-01`)

---

[← Watering Hole Attacks](../ing/MC-ING-06.md) | [User-Executed Files →](../act/MC-ACT-01.md)
