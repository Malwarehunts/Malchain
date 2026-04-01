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

**MC-ING-01** - Removable Media & File Transfer - This capability introduces attacker-controlled artifacts via physical or logical transfer. Execution typically depends on user interaction, making awareness and device controls critical.

**MC-ING-02** - Malvertising & Drive-By Downloads - This capability abuses the web ecosystem to silently deliver malicious content. Attackers leverage browser trust, advertising platforms, and redirect chains.

**MC-ING-03** - Supply Chain Compromise - Supply chain compromise weaponized trust in vendors, software updates, and dependencies. This capability enables high-trust delivery and often bypasses traditional security controls.

**MC-ING-04** - Credential Abuse - Credential abuse leverages valid authentication material to gain authorized access. This capability often bypasses perimeter defenses and directly enables execution.

**MC-ING-05** - Malicious or Compromised USB Devices - Peripheral trust abuse allows attackers to introduce execution logic through device classes such as HID, storage, or network adapters, often with minimal user interaction.

**MC-ING-06** - Watering Hole Attacks - Watering hole attacks compromise trusted websites to deliver malicious content selectively to high-value targets, reducing exposure and detection.

**MC-ING-07** - External Remote Services - External remote services ingress exploits exposed VPNs, RDP, cloud portals, and SaaS platforms to gain authenticated or network-level access.

INGRESS capabilities often overlap and reinforce one another. For example, credential abuse may follow malvertising, or supply chain compromise may enable remote service abuse.