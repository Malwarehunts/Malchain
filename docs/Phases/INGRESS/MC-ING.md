## INGRESS

## Phase Overview

The INGRESS phase encompasses all techniques and capabilities that result in an attacker gaining an initial foothold within an environment. Unlike later phases, INGRESS focuses on entry, trust establishment, and delivery of access rather than execution logic. The transition from INGRESS to ACTIVATION occurs when attacker-controlled logic can be executed. This transition point is critical for detection and disruption. INGRESS capabilities often overlap and reinforce one another. For example, credential abuse may follow malvertising, or supply chain compromise may enable remote service abuse.
  
INGRESS ends when execution becomes possible, at which point ACTIVATION begins. INGRESS capabilities are defined by the type of trust abused:

* Human trust (users, credentials, awareness)
* Software trust (updates, dependencies, vendors)
* Hardware trust (peripherals and removable devices)
* Network trust (remote connectivity and services)
* Web trust (advertising, websites, and browsing behavior)
* Partner or third-party trust relationships
* System exposure trust (externally accessible services)

Defensive efforts during INGRESS should prioritize visibility into:

* Identity authentication and login activity
* Software integrity and update mechanisms
* Peripheral and device connection events
* Web and browser activity patterns
* Network access and remote service exposure
* Vendor and third-party integration behavior
* Initial access attempts and authentication anomalies

**[MC-ING-01](/docs/Phases/INGRESS/SUB-Phases/MC-ING-01.md)** - Removable Media & File Transfer - This capability introduces attacker-controlled artifacts into an environment through physical or logical transfer mechanisms. Attackers rely on users to open files or connect storage devices, enabling the introduction of malicious content without direct network interaction. Because removable media is often used for legitimate data transfer, malicious files may appear routine. Monitoring device connections and restricting unauthorized file execution are critical defensive measures.

**[MC-ING-02](/docs/Phases/SUB-Phases/MC-ING.O2.md)** - Malvertising & Drive-By Downloads - Malvertising and drive-by downloads abuse the web ecosystem to silently deliver malicious content to users. Attackers leverage browser trust, advertising platforms, and redirect chains to initiate downloads or script execution without explicit user awareness. Because the delivery occurs through legitimate websites or advertisements, detection can be difficult. Monitoring web traffic behavior and enforcing browser security controls are essential defensive strategies.

**[MC-ING-03](/docs/Phases/SUB-Phases/MC-ING.O3.md)** - Supply Chain Compromise - Supply chain compromise weaponizes trust in vendors, software updates, and dependencies to deliver malicious code. Attackers compromise trusted software providers or distribution mechanisms to insert malicious functionality into legitimate products. Because the delivery originates from a trusted source, traditional security controls may not detect the threat. Verifying software integrity and monitoring update processes are critical defensive measures.

**[MC-ING-04](/docs/Phases/SUB-Phases/MC-ING.O4.md)** - Credential Abuse - Credential abuse leverages valid authentication material to gain authorized access to systems or services. Attackers use stolen passwords, tokens, or session credentials to bypass perimeter defenses and appear as legitimate users. Because authentication events appear normal, detection often relies on behavioral anomalies rather than technical signatures. Monitoring login patterns and enforcing strong authentication controls are key defensive strategies.

**[MC-ING-05](/docs/Phases/SUB-Phases/MC-ING.O5.md)** - Malicious or Compromised USB Devices - Malicious or compromised USB devices exploit peripheral trust to introduce execution logic into a system. Attackers design devices that emulate keyboards, storage media, or network adapters to automatically perform actions when connected. Because devices may appear legitimate, execution can occur with minimal user interaction. Monitoring device behavior and enforcing hardware control policies are essential defensive measures.

**[MC-ING-06](/docs/Phases/SUB-Phases/MC-ING.O6.md)** - Watering Hole Attacks - Watering hole attacks compromise trusted websites to deliver malicious content selectively to targeted users. Attackers identify websites frequently visited by specific organizations or groups and inject malicious code into those sites. This targeted delivery reduces exposure and increases the likelihood of successful compromise. Monitoring web access patterns and securing trusted partner websites are important defensive controls.

**[MC-ING-07](/docs/Phases/SUB-Phases/MC-ING.O7.md)** - External Remote Services - External remote services ingress exploits exposed network services such as VPNs, remote desktop systems, cloud portals, and software-as-a-service platforms. Attackers attempt to authenticate or connect directly to accessible services to gain entry into the environment. Because these services are designed for legitimate remote access, misuse may appear routine. Monitoring remote access activity and enforcing access restrictions are critical defensive measures.

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

