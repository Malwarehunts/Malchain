# ACTIVATION

## Phase Overview

The ACTIVATION phase encompasses all techniques and capabilities that result in attacker-controlled logic being executed within an environment. Unlike INGRESS, which focuses on entry and trust establishment, ACTIVATION focuses on process creation, runtime control, and operational capability. The transition from ACTIVATION to ANCHORING occurs when execution becomes repeatable or persistent without requiring repeated access events. This transition point is critical for containment and response.

ACTIVATION ends when persistence becomes reliable, at which point ANCHORING begins. ACTIVATION capabilities are defined by the mechanism used to execute logic within the system:

- User execution trust (human-triggered actions)
- Interpreter trust (scripts and runtime engines)
- Service and system process trust
- Application and library loading trust
- Management interface trust (administrative tooling)
- Firmware and boot trust (pre-operating system control)
- Scheduled or automated execution trust

Defensive efforts during ACTIVATION should prioritize visibility into:

- Process creation and execution context
- Command-line and script interpreter usage
- Service and scheduled task creation
- Module and library loading behavior
- Remote command execution activity
- Privilege changes and execution scope

**User-Executed Files** - This capability relies on user interaction to initiate execution of attacker-controlled files. Execution often occurs through email attachments, downloads, shared files, or removable media. The success of this capability depends on social engineering, trust in file sources, and user behavior. Security awareness, application control, and file reputation systems are critical defensive measures.

**Script-Based Execution** - This capability leverages scripting environments to execute commands or payloads without requiring compiled binaries. Attackers use interpreters such as command shells or scripting engines to perform system actions dynamically. Script execution enables flexible control, rapid deployment, and fileless operation. Monitoring interpreter usage and command execution patterns is essential for detection.

**Service-Based Execution** - Service-based execution abuses trusted system services to run attacker-controlled processes. Attackers create or modify services to execute code automatically or with elevated privileges. Because services are designed for persistent and privileged operation, misuse can provide reliable system control. Service configuration monitoring and privilege management are key defensive controls.

**DLL Side-Loading or Hijacking** - This capability exploits the way applications load libraries during execution. Attackers place malicious libraries in locations where trusted applications will load them automatically. The trusted application executes the malicious code without direct user interaction. Library validation and application integrity controls are important defensive measures.

**WMI-Based Execution** - Windows Management Instrumentation (WMI) execution uses built-in administrative interfaces to run commands or scripts remotely or locally. Attackers leverage WMI to execute logic without creating traditional processes or files. Because WMI is a legitimate management tool, misuse can blend with normal administrative activity. Monitoring administrative command execution and remote management activity is critical.

**Browser Extension Execution** - Browser extension execution abuses the trust placed in browser add-ons or plugins. Attackers install or modify extensions to execute scripts within browser sessions. Because extensions operate within trusted user environments, they can access credentials, sessions, and data. Extension management and browser security policies are important defensive controls.

**Boot or Firmware Execution** - Boot or firmware execution occurs before the operating system fully initializes. Attackers modify firmware or boot components to execute code at system startup. This capability provides deep system control and can bypass operating system defenses. Secure boot mechanisms and firmware integrity validation are critical defensive measures.

## Compilation table

| Capability                  | Trust Abused         | Typical Output         | Detection Priority | Telemetry Source  | Best Disruption Point |
| --------------------------- | -------------------- | ---------------------- | ------------------ | ----------------- | --------------------- |
| User Execution              | User Trust           | Process Creation       | High               | Endpoint          | Application Control   |
| Script Execution            | Interpreter          | Script Runtime         | High               | Endpoint          | Script Blocking       |
| Service Execution           | System Services      | Service Process        | High               | Endpoint          | Service Monitoring    |
| DLL Side-Loading            | Application Trust    | Module Load            | Critical           | Endpoint          | Library Validation    |
| WMI Execution               | Management Interface | Remote Execution       | High               | Endpoint, Network | WMI Restrictions      |
| Scheduled / Task Execution  | Scheduler Trust      | Recurring Execution    | High               | Endpoint          | Task Restrictions     |
| Browser Extension Execution | Browser Trust        | Extension Runtime      | Medium             | Endpoint          | Extension Control     |
| Boot / Firmware Execution   | Firmware / Boot      | Pre-OS Execution       | Critical           | Endpoint          | Secure Boot           |
| Remote Command Execution    | Remote Admin Tools   | Remote Process         | High               | Endpoint, Network | Access Control        |
| Embedded / API Execution    | Application APIs     | Programmatic Execution | Medium             | Endpoint          | API Restrictions      |
