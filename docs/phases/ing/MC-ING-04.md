# ING-04 · Credential Abuse

**Phase:** [Ingress](../ing.md) · Initial Access  |  **Detections:** KQL

[← Back to Ingress](../ing.md) · [Chain Linking](../../LINKING.md) · [Detection Library](../../DETECTIONS.md)

---

## Summary

Credential Abuse refers to the use of valid authentication material obtained through theft, guessing, reuse, or compromise to gain unauthorized access. Unlike exploitation-based ingress, credential abuse leverages legitimate authentication mechanisms. Within MalChain, this capability ends once authenticated access is achieved and execution opportunities become available. Attackers exploit trust placed in:
	
*   Username/password authentication
*   Session tokens and cookies
*   API keys and secrets
*   Federated identity systems
  
Successful authentication often bypasses perimeter defenses entirely. Common abuse patterns include:
	
*   Phishing-derived credential use
*   Password spraying
*   Credential stuffing
*   Reuse of leaked credentials
*   Abuse of service accounts
  
Real world usage includes:

*   Ransomware initial access
*   Cloud account takeover campaigns
*   Business email compromise
*   Advanced persistent threat operations

## Detection Guidance

Detection relies on authentication telemetry, behavioral baselining, and correlation across identity, endpoint, and network signals. Detection strategies includes:
	
*   Detect anomalous login patterns
*   Monitor failed-to-success login sequences
*   Identify impossible travel scenarios
*   Alert on credential use outside business hours
*   Detect service account misuse

## KQL Detection Concepts

*   Multiple authentication attempts from a single IP
*   Successful login after multiple failures
*   Login from rare geographic locations

## YARA Detection Concepts

*   Embedded credentials in malware
*   Hardcoded API tokens
*   Credential harvesting routines

## KQL Detection Rule

```kql
// Credential Abuse: successful sign-ins from anomalous locations / impossible travel (identity)
IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| summarize Countries=dcount(tostring(parse_json(AdditionalFields).Country)), Locations=make_set(tostring(parse_json(AdditionalFields).Country)) by AccountUpn, bin(Timestamp, 1h)
| where Countries > 1
| project Timestamp, AccountUpn, Countries, Locations
```

## YARA Detection Rule

_YARA is not meaningfully applicable to this primarily behavioral / network-telemetry capability. Rely on the KQL rule above plus network and identity detections._

## Mitigation

*   Enforce strong password policies
*   Enable multi-factor authentication
*   Monitor and rotate credentials
*   Limit service account privileges

## Incident Response

*   Reset compromised credentials
*   Invalidate sessions and tokens
*   Review accessed resources
*   Hunt for follow-on execution

## Chain Linking

`INGRESS → Authenticated Access → ACTIVATION`

**Enables next:**

- [Service-Based Execution](../act/MC-ACT-03.md) (`ACT-03`)
- [WMI-Based Execution](../act/MC-ACT-05.md) (`ACT-05`)
- [Cloud & Hybrid Lateral Movement](../exp/MC-EXP-10.md) (`EXP-10`)

---

[← Supply Chain Compromise](../ing/MC-ING-03.md) | [Malicious or Compromised USB Devices →](../ing/MC-ING-05.md)
