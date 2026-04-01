## INGRESS

## Phase Overview

The INGRESS phase encompasses all techniques and capabilities that result in an attacker gaining an initial foothold within an environment. Unlike later phases, INGRESS focuses on entry, trust establishment, and delivery of access rather than execution logic. The transition from INGRESS to ACTIVATION occurs when attacker-controlled logic can be executed. This transition point is critical for detection and disruption.  
  
INGRESS ends when execution becomes possible, at which point ACTIVATION begins. INGRESS capabilities are defined by the type of trust abused:

*   Human trust (users, credentials)
*   Software trust (updates, dependencies)
*   Hardware trust (peripherals)
*   Network trust (remote services)
*   Web trust (advertising, websites)

Defensive efforts during INGRESS should prioritize visibility into:

*   Identity authentication
*   Software integrity
*   Peripheral activity
*   Web and network exposure

**[MC-ING-01](/SUB-Phases/MC-ING.O1.md)** - Removable Media & File Transfer - This capability introduces attacker-controlled artifacts via physical or logical transfer. Execution typically depends on user interaction, making awareness and device controls critical.

**[MC-ING-02](/SUB-Phases/MC-ING.O2.md)** - Malvertising & Drive-By Downloads - This capability abuses the web ecosystem to silently deliver malicious content. Attackers leverage browser trust, advertising platforms, and redirect chains.

**[MC-ING-03](/SUB-Phases/MC-ING.O3.md)** - Supply Chain Compromise - Supply chain compromise weaponized trust in vendors, software updates, and dependencies. This capability enables high-trust delivery and often bypasses traditional security controls.

**[MC-ING-04](/SUB-Phases/MC-ING.O4.md)** - Credential Abuse - Credential abuse leverages valid authentication material to gain authorized access. This capability often bypasses perimeter defenses and directly enables execution.

**[MC-ING-05](/SUB-Phases/MC-ING.O5.md)** - Malicious or Compromised USB Devices - Peripheral trust abuse allows attackers to introduce execution logic through device classes such as HID, storage, or network adapters, often with minimal user interaction.

**[MC-ING-06](/SUB-Phases/MC-ING.O6.md)** - Watering Hole Attacks - Watering hole attacks compromise trusted websites to deliver malicious content selectively to high-value targets, reducing exposure and detection.

**[MC-ING-07](/SUB-Phases/MC-ING.O7.md)** - External Remote Services - External remote services ingress exploits exposed VPNs, RDP, cloud portals, and SaaS platforms to gain authenticated or network-level access.

INGRESS capabilities often overlap and reinforce one another. For example, credential abuse may follow malvertising, or supply chain compromise may enable remote service abuse.

## Compilation table

| Capability        | Trust Abused       | Typical Output       | Detection Priority | Telemetry Source                    | Best Disruption Point    |
| ----------------- | ------------------ | -------------------- | ------------------ | ----------------------------------- | ------------------------ |
| Removable Media   | Human / Device     | File Artifact        | Medium             | Endpoint                            | Autorun Disable          |
| Malvertising      | Web / Browser      | Script or Download   | Medium             | Endpoint , Network                  | Script Blocking          |
| Supply Chain      | Software Vendor    | Trusted Execution    | Critical           | Endpoint , Network                  | Signature Validation     |
| Credential Abuse  | Identity           | Authenticated Access | Critical           | Identity, Cloud                     | MFA & Conditional Access |
| Malicious USB     | Hardware           | Immediate Execution  | Low-Medium         | Endpoint                            | Device Control           |
| Watering Hole     | Web / Partner      | Targeted Delivery    | Low-Medium         | Endpoint , Network                  |                          |
| External Services | Network / Identity | Remote Access        | High               |  Endpoint, Network, Identity, Cloud | Access Restrictions      |

