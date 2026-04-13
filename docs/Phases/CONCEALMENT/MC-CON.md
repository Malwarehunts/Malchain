# CONCEALMENT

## Phase Overview

The CONCEALMENT phase encompasses all techniques and capabilities that reduce visibility of attacker activity and delay detection within an environment. Unlike ANCHORING, which focuses on maintaining reliable access, CONCEALMENT focuses on stealth, evasion, and operational longevity. The transition from CONCEALMENT to EXPANSION occurs when attackers begin using hidden access to move laterally, escalate privileges, or broaden control across systems. This transition point is critical for identifying coordinated attacker behavior before widespread compromise occurs.

CONCEALMENT ends when attacker activity shifts from hiding presence to expanding control, at which point EXPANSION begins. CONCEALMENT capabilities are defined by the method used to obscure execution, manipulate evidence, or evade defensive controls:

- Code and binary trust (execution visibility)
- Memory and runtime trust (artifact visibility)
- Security control trust (protection integrity)
- Identity and process trust (legitimacy perception)
- Environment and analysis trust (detection context)
- System logging and artifact trust (evidence reliability)
- Behavioral detection trust (pattern recognition)

Defensive efforts during CONCEALMENT should prioritize visibility into:

- Unusual process and memory behavior
- Security control status and configuration changes
- Identity and process impersonation indicators
- Execution patterns inconsistent with baseline behavior
- Logging integrity and event reliability
- Repeated system cleanup or artifact removal activity
- Indicators of adaptive or polymorphic behavior

**Obfuscation & Packing** - This capability hides malicious logic by transforming code into formats that are difficult to analyze or detect. Attackers use encoding, compression, or encryption to disguise executable content and bypass signature-based detection. Packed or obfuscated code often appears benign until it is unpacked during execution. Monitoring binary structure changes and unusual execution patterns is essential for detection.

**File less Malware Execution** - File less malware execution runs malicious logic directly in system memory without creating traditional file artifacts. Attackers use scripting engines, memory injection, or system utilities to perform actions without writing files to disk. Because file-based detection relies on visible artifacts, fileless execution reduces detection opportunities. Monitoring runtime behavior and memory activity is critical for identifying this capability.

**Security Tool Tampering** - Security tool tampering disables, modifies, or bypasses defensive mechanisms such as antivirus software, monitoring agents, or logging systems. Attackers attempt to reduce detection capability before performing additional actions. This capability directly weakens defensive visibility and increases attacker dwell time. Continuous monitoring of security control health and configuration changes is essential.

**Masquerading & Impersonation** - Masquerading and impersonation create the appearance of legitimate system or user activity. Attackers rename files, mimic trusted processes, or use legitimate account credentials to blend into normal operations. Because defensive systems rely on trust in known identities, impersonation can delay detection. Validating process identity and monitoring unusual account behavior are key defensive measures.

**Environment & Sandbox Evasion** - Environment and sandbox evasion detects whether execution is occurring in a monitored or analysis environment. Attackers design code to behave differently when security tools or virtualized environments are detected. This capability prevents automated analysis and delays detection. Monitoring conditional execution behavior and system environment checks is important for identifying evasion attempts.

**Process Injection** - Process injection inserts malicious code into legitimate running processes. This allows attacker logic to execute within trusted system components, making detection more difficult. Injected code inherits the permissions and visibility of the host process. Monitoring process memory activity and unexpected inter-process behavior is essential for detecting this capability.

**Polymorphism & Metamorphism** - Polymorphism and metamorphism continuously modify malicious code to evade detection. Attackers generate new variants of code while preserving functionality. This capability disrupts signature-based detection and complicates analysis. Monitoring behavioral patterns rather than static signatures is critical for identifying polymorphic activity.

**Log & Artifact Manipulation** \- Log and artifact manipulation alters or removes system records to hide evidence of attacker activity. Attackers delete logs, modify timestamps, or suppress event generation to prevent detection and forensic reconstruction. Because security monitoring relies on accurate records, tampering with logs significantly reduces visibility. Ensuring log integrity and centralized logging is essential.

**Living-off-the-Land for Evasion** - Living-off-the-land for evasion uses legitimate system tools and built-in utilities to perform malicious actions. Attackers rely on trusted programs already present in the environment to avoid introducing suspicious files. This capability reduces the number of detectable artifacts and blends activity into normal system operations. Monitoring command usage patterns and abnormal tool behavior is important for detection.

**Anti-Forensics & Cleanup** - Anti-forensics and cleanup remove traces of attacker activity after operations are completed. Attackers delete temporary files, clear logs, and remove persistence artifacts to reduce evidence of compromise. This capability complicates incident response and forensic analysis. Monitoring repeated cleanup actions and sudden loss of historical data is critical for identifying anti-forensic behavior.

## Compilation Table

| Capability                    | Trust Abused         | Typical Output         | Detection Priority | Telemetry Source | Best Disruption Point |
| ----------------------------- | -------------------- | ---------------------- | ------------------ | ---------------- | --------------------- |
| Obfuscation & Packing         | Code Trust           | Hidden Logic           | Medium             | Endpoint         | Code Inspection       |
| Fileless Malware              | Memory               | Runtime Artifact       | High               | Endpoint         | Behavior Monitoring   |
| Disabling Security Tools      | Security Controls    | Protection Loss        | Critical           | Endpoint         | Tamper Protection     |
| Masquerading                  | User Trust           | False Identity         | Medium             | Endpoint         | Process Validation    |
| Environment / Sandbox Evasion | Analysis Environment | Conditional Execution  | Medium             | Endpoint         | Behavior Analysis     |
| Process Injection             | System Processes     | Injected Code          | Critical           | Endpoint         | Process Monitoring    |
| Polymorphism / Metamorphism   | Detection Logic      | Variant Code           | Medium             | Endpoint         | Signature Updates     |
| Log Manipulation              | Audit Logs           | Missing Evidence       | High               | Endpoint         | Log Integrity         |
| Living-off-the-Land Evasion   | Trusted Tools        | Legitimate Command Use | Medium             | Endpoint         | Command Monitoring    |
| Anti-Forensics Cleanup        | System Artifacts     | Evidence Removal       | High               | Endpoint         | Retention Controls    |
