# ANCHORING

## Phase Overview

The ANCHORING phase encompasses all techniques and capabilities that enable attackers to maintain reliable access within an environment over time. Unlike ACTIVATION, which focuses on executing attacker-controlled logic, ANCHORING focuses on persistence, survivability, and re-entry following system restarts, logoffs, or environmental changes. The transition from ANCHORING to CONCEALMENT occurs when persistence mechanisms are deliberately hidden, hardened, or modified to evade detection and analysis. This transition point is critical for long-term containment and eradication.

ANCHORING ends when persistence becomes covert or resilient against defensive monitoring, at which point CONCEALMENT begins. ANCHORING capabilities are defined by the persistence mechanism used to maintain system presence:

- Session and startup trust (logon behavior)
- Scheduler and automation trust
- Service and background process trust
- System configuration trust (registry and settings)
- Application and browser trust
- Management interface trust (event-driven execution)
- Memory and runtime trust
- Firmware and boot trust

Defensive efforts during ANCHORING should prioritize visibility into:

- Startup and logon execution changes
- Scheduled task and automation configuration
- Service and daemon lifecycle events
- Registry and configuration modifications
- Persistent application or browser components
- Event subscription and management interface activity
- Memory-resident execution behavior
- Firmware and boot configuration integrity

**Startup & Logon Execution** - This capability establishes persistence by configuring programs to run automatically when a user logs into the system or when the system starts. Attackers modify startup folders, login scripts, or system initialization settings to ensure execution occurs without manual intervention. Because startup processes are routine system behavior, malicious entries can remain undetected for extended periods. Monitoring startup configuration changes and restricting unauthorized auto-run behavior are critical defensive measures.

**Scheduled & Triggered Execution** - Scheduled and triggered execution persistence relies on automated mechanisms that execute commands at predefined times or in response to system events. Attackers create scheduled tasks or event triggers that repeatedly launch malicious logic. These mechanisms provide reliable execution while minimizing user interaction. Continuous monitoring of scheduling systems and event-driven execution activity is essential for early detection.

**Service & Daemon Persistence** - Service and daemon persistence uses long-running background processes to maintain system presence. Attackers create or modify services to automatically start during system initialization or remain active continuously. Because services often operate with elevated privileges and minimal visibility to users, misuse can provide durable control. Service configuration auditing and privilege management are important defensive controls.

**Registry-Based Persistence** \- Registry-based persistence modifies system configuration settings to ensure malicious programs execute automatically or maintain system control. Attackers create or alter registry entries that define startup behavior, execution paths, or system policies. These changes may persist across reboots and user sessions. Monitoring registry modifications and enforcing configuration integrity are essential defensive strategies.

**Browser-Based Persistence** - Browser-based persistence abuses trusted browser components to maintain ongoing access within user sessions. Attackers install extensions, modify browser settings, or manipulate session storage to ensure repeated execution of scripts or commands. Because browsers are widely used and frequently trusted, malicious persistence can blend with normal activity. Browser configuration management and extension control policies are key defensive measures.

**WMI & Event Subscription Persistence** - WMI and event subscription persistence uses system management infrastructure to trigger execution in response to specific system conditions. Attackers create event subscriptions that automatically run commands when defined events occur, such as system startup or process creation. These mechanisms operate silently and can remain hidden within system management frameworks. Monitoring event subscription creation and management interface activity is critical for detection.

**File less & In-Memory Persistence** - File less and in-memory persistence stores execution logic within system memory rather than on disk. Attackers use memory-resident techniques to maintain presence without leaving traditional file artifacts. This approach reduces forensic visibility and complicates detection. Monitoring memory activity and behavioral indicators is essential for identifying this capability.

**Boot & Pre-OS Persistence** - Boot and pre-operating system persistence modifies firmware or boot components to execute malicious logic before the operating system loads. This capability provides deep system control and allows attackers to maintain presence even after system reinstallation. Because these components operate outside normal operating system controls, detection and remediation can be challenging. Firmware integrity validation and secure boot mechanisms are critical defensive measures.
