# EXPANSION

## Phase Overview

The EXPANSION phase encompasses all techniques and capabilities that allow attackers to broaden their control across systems, accounts, and infrastructure within an environment. Unlike CONCEALMENT, which focuses on hiding presence, EXPANSION focuses on movement, privilege growth, and operational reach. The transition from EXPANSION to EXTRACTION occurs when attackers shift from gaining access to leveraging that access for data movement, command control, or operational impact. This transition point is critical for preventing widespread compromise and limiting damage.

EXPANSION ends when attacker activity shifts from movement and control to data transfer or external command coordination, at which point EXTRACTION begins. EXPANSION capabilities are defined by the mechanisms used to access additional systems, elevate privileges, and extend operational control:

- Administrative tool trust (built-in utilities and system commands)
- Identity and authentication trust (credentials and tokens)
- Network service trust (remote protocols and services)
- File sharing and system connectivity trust
- Privilege and authorization trust (access control boundaries)
- Directory and domain trust relationships
- Cloud and hybrid infrastructure trust

Defensive efforts during EXPANSION should prioritize visibility into:

- Remote access and authentication patterns
- Privilege escalation events
- Credential usage across multiple systems
- Unusual service or protocol activity
- Lateral movement across network segments
- Domain and directory service changes
- Cross-environment and cloud access behavior

**Living-off-the-Land Lateral Movement** - This capability uses legitimate administrative tools and built-in system utilities to move between systems. Attackers leverage trusted commands and management features to execute actions without introducing new software. Because these tools are commonly used by administrators, malicious use can blend with routine operations. Monitoring command usage patterns and restricting unnecessary administrative tools are essential defensive measures.

**Credential Reuse & Relay** - Credential reuse and relay leverage valid authentication material to access additional systems or services. Attackers reuse stolen passwords, tokens, or session credentials to authenticate without triggering security alerts. This capability allows movement across systems while appearing as legitimate user activity. Monitoring authentication patterns and enforcing strong identity controls are critical for detection.

**Pass-the-Hash / Pass-the-Ticket** - Pass-the-hash and pass-the-ticket techniques allow attackers to authenticate using captured authentication data rather than plaintext credentials. These methods exploit authentication mechanisms to bypass password-based protections. Because authentication appears legitimate, detection can be challenging. Monitoring authentication anomalies and protecting credential storage mechanisms are key defensive strategies.

**Remote Service & Protocol Abuse** - Remote service and protocol abuse exploit network services such as remote administration or file transfer mechanisms to execute commands on other systems. Attackers use trusted communication protocols to establish connections and control remote systems. Because these protocols are designed for legitimate system management, misuse may not immediately appear suspicious. Monitoring remote service usage and enforcing strict access controls are essential.

**Network Share Propagation** - Network share propagation spreads attacker access by copying files or scripts across shared storage locations accessible to multiple systems. Attackers use shared resources to distribute execution logic and extend presence within the network. This capability allows rapid expansion without requiring direct system compromise. Monitoring file access patterns and controlling share permissions are important defensive measures.

**Worm-like Self-Propagation** - Worm-like self-propagation automatically spreads attacker activity across systems without direct user interaction. Attackers design code to identify new targets and replicate itself across network connections. This capability enables rapid expansion and can overwhelm defensive controls. Network segmentation and monitoring unusual connection patterns are critical for limiting spread.

**Privilege Escalation Across Hosts** - Privilege escalation across hosts increases attacker authority within systems or across environments. Attackers exploit configuration weaknesses, vulnerabilities, or misconfigured permissions to gain higher-level access. Elevated privileges allow broader control and reduce defensive restrictions. Monitoring privilege changes and enforcing least-privilege access are essential defensive controls.

**Identity & Trust Relationship Abuse** - Identity and trust relationship abuse exploit relationships between systems, domains, or organizations to access additional resources. Attackers use established trust connections to bypass security boundaries and gain indirect access to protected systems. Because trust relationships are designed to facilitate cooperation, misuse can expand access quickly. Monitoring cross-domain activity and validating trust configurations are critical defensive measures.

**Directory Services Targeting** - Directory services targeting focuses on manipulating or querying centralized identity management systems to gain control over users, groups, or permissions. Attackers modify directory configurations or collect identity information to expand their reach. Because directory services govern authentication and authorization, compromise can affect the entire environment. Monitoring directory changes and enforcing strong administrative controls are key defenses.

**Cloud & Hybrid Lateral Movement** - Cloud and hybrid lateral movement extends attacker control across cloud services, virtual environments, or hybrid infrastructure. Attackers leverage cloud identities, service accounts, and integration points to access additional systems beyond traditional networks. Because cloud environments often rely on centralized identity management, misuse can propagate quickly. Monitoring cloud access patterns and enforcing identity governance are essential for detection and containment.

## Compilation Table

| Capability                        | Trust Abused         | Typical Output        | Detection Priority | Telemetry Source  | Best Disruption Point |
| --------------------------------- | -------------------- | --------------------- | ------------------ | ----------------- | --------------------- |
| Living-off-the-Land Movement      | Trusted Tools        | Remote Execution      | High               | Endpoint, Network | Tool Restrictions     |
| Credential Reuse                  | Identity             | Remote Access         | Critical           | Identity, Network | Credential Rotation   |
| Pass-the-Hash / Ticket            | Authentication Trust | Authenticated Session | Critical           | Identity          | Credential Protection |
| Remote Service Abuse              | Network Services     | Remote Execution      | High               | Endpoint, Network | Service Restrictions  |
| Network Share Propagation         | File Sharing         | File Spread           | High               | Endpoint, Network | Share Controls        |
| Privilege Escalation Across Hosts | System Privileges    | Elevated Access       | Critical           | Endpoint          | Privilege Controls    |
| Trust Relationship Abuse          | Domain Trust         | Cross-System Access   | Critical           | Identity          | Trust Restrictions    |
| Directory Services Targeting      | Directory Services   | Account Control       | Critical           | Identity          | Directory Monitoring  |
| Cloud / Hybrid Lateral Movement   | Cloud Identity       | Cloud Access          | High               | Cloud             | Access Policies       |
| Worm-like Propagation             | Network Trust        | Rapid Spread          | Critical           | Network           | Segmentation          |

