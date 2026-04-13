# EXTRACTION

## Phase Overview

The EXTRACTION phase encompasses all techniques and capabilities that enable attackers to transfer data, maintain external command control, or achieve operational impact outside the compromised environment. Unlike EXPANSION, which focuses on gaining broader access and control, EXTRACTION focuses on data movement, communication, and operational outcomes. The transition from EXPANSION to EXTRACTION occurs when attacker activity shifts from internal movement to outbound transfer or coordination. This transition point is critical for preventing data loss, protecting sensitive information, and containing operational damage.

EXTRACTION ends when attacker activity results in successful data transfer, sustained external command coordination, or operational leverage, completing the attack lifecycle. EXTRACTION capabilities are defined by the communication or transfer mechanism used to move data or control signals beyond the environment:

- Network communication trust (web and protocol traffic)
- Domain name and routing trust (DNS infrastructure)
- Cloud storage and service trust
- Messaging and communication platform trust
- File transfer protocol trust
- Network anonymization trust (proxy and routing services)
- Encryption and secure channel trust
- Physical media trust (portable storage devices)
- Data encoding and concealment trust
- Multi-channel communication trust

Defensive efforts during EXTRACTION should prioritize visibility into:

- Outbound network traffic patterns
- Data transfer volume and frequency
- External communication destinations
- Cloud storage and synchronization activity
- Messaging and file-sharing platform usage
- Encrypted communication sessions
- Removable media activity
- Unusual or redundant communication channels

**HTTP / HTTPS Data Exfiltration** - This capability transfers data using standard web protocols that are commonly allowed through network security controls. Attackers send data through web requests or responses to external servers, often blending with normal internet traffic. Because web communication is essential for business operations, malicious transfers may appear legitimate. Monitoring outbound traffic patterns and inspecting web communication behavior are critical defensive measures.

**DNS Tunneling** - DNS tunneling uses domain name system communication to encode and transmit data within routine DNS queries and responses. Attackers exploit the trust placed in DNS infrastructure to bypass network restrictions and maintain covert communication channels. Because DNS traffic is frequent and widely permitted, malicious use can remain unnoticed. Monitoring DNS query patterns and unusual domain activity is essential for detection.

**Cloud Storage Abuse** - Cloud storage abuse transfers data to external storage services using legitimate cloud platforms. Attackers upload files to trusted cloud environments to avoid detection and maintain access to stolen data. Because cloud services are widely used for collaboration and backup, malicious transfers may blend with routine activity. Monitoring cloud synchronization behavior and enforcing data governance controls are key defensive strategies.

**Messaging and Social Platform Channels** - Messaging and social platform channels use communication applications to transmit data or commands. Attackers leverage trusted communication tools to move information between systems or coordinate operations. Because these platforms are commonly used for collaboration, malicious activity may appear routine. Monitoring communication patterns and controlling data sharing capabilities are important defensive measures.

**FTP / SFTP / FTPS Transfer** - This capability transfers files using dedicated file transfer protocols designed for reliable data movement. Attackers use these protocols to move large volumes of data efficiently and securely. Because file transfer services are often used for legitimate operations, malicious transfers may not immediately trigger alerts. Monitoring transfer activity and restricting unauthorized file transfer services are essential defenses.

**Tor / Proxy / VPN Anonymization Channels** - Tor, proxy, and VPN channels conceal the origin and destination of network traffic by routing communication through intermediary systems. Attackers use anonymization networks to hide their location and maintain persistent communication with compromised systems. Because these technologies are designed to protect privacy, misuse can complicate detection and investigation. Monitoring anonymized traffic patterns and controlling network routing behavior are critical defensive measures.

**Encrypted Command-and-Control Channels** - Encrypted command-and-control channels establish secure communication between attackers and compromised systems. Attackers use encryption to protect commands and data from interception or inspection. Because encrypted communication is widely used for legitimate purposes, malicious channels may appear normal. Monitoring encrypted traffic behavior and validating communication endpoints are essential defensive strategies.

**Removable Media Data Extraction** - Removable media data extraction transfers information using portable storage devices such as USB drives or external disks. Attackers use physical devices to remove data from isolated or restricted environments. Because physical transfer bypasses network monitoring, detection opportunities may be limited. Monitoring device usage and enforcing removable media controls are important defensive measures.

**Stenographic Data Transfer** - Stenographic data transfer conceals information within other files, such as images, audio, or documents. Attackers embed data within seemingly harmless content to evade detection during transmission. Because the carrier files appear legitimate, traditional security controls may not identify hidden information. Monitoring file structure anomalies and inspecting content integrity are key defensive techniques.

**Multi-Channel Redundant Exfiltration** - Multi-channel redundant exfiltration uses multiple communication methods simultaneously or sequentially to ensure successful data transfer. Attackers implement fallback channels to maintain communication if one method is blocked. This capability increases resilience and reduces the likelihood of disruption. Monitoring coordinated communication patterns and blocking redundant channels are critical defensive measures.

## Compilation Table

| Capability                           | Trust Abused           | Typical Output     | Detection Priority | Telemetry Source  | Best Disruption Point  |
| ------------------------------------ | ---------------------- | ------------------ | ------------------ | ----------------- | ---------------------- |
| HTTP / HTTPS Data Exfiltration       | Web Trust              | Data Transfer      | Critical           | Network           | Outbound Filtering     |
| DNS Tunneling                        | DNS Trust              | Encoded Traffic    | Critical           | Network           | DNS Monitoring         |
| Cloud Storage Abuse                  | Cloud Trust            | Data Upload        | Critical           | Cloud             | Storage Controls       |
| Messaging / Social Channels          | Communication Trust    | File Transfer      | High               | Endpoint, Network | Communication Controls |
| FTP / SFTP Transfer                  | File Transfer Services | File Upload        | High               | Network           | Transfer Restrictions  |
| Tor / Proxy / VPN Channels           | Network Routing        | Hidden Traffic     | High               | Network           | Tunnel Blocking        |
| Encrypted Command & Control          | Encryption Trust       | Secure Channel     | Critical           | Network           | Traffic Inspection     |
| Removable Media Extraction           | Physical Access        | Data Removal       | Medium             | Endpoint          | Device Control         |
| Steganographic Transfer              | File Trust             | Hidden Data        | Medium             | Endpoint          | Content Inspection     |
| Multi-Channel Redundant Exfiltration | Multiple Trust Paths   | Resilient Transfer | Critical           | Network           | Channel Blocking       |


