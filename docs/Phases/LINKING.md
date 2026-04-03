## MALCHAIN Linking
MalChain linking describes how actions in one phase logically enable the next phase in a continuous attack lifecycle, forming a deterministic chain from initial access to final impact. Each phase consumes the outputs of the previous phase—for example, Ingress provides access, Activation executes logic, Anchoring maintains persistence, Concealment reduces visibility, Expansion increases reach, and Extraction delivers operational impact. The relationships are directional and state-based, meaning changes in trust, privilege, or control propagate forward through the chain. This linking model allows analysts to reconstruct incidents, correlate telemetry across phases, and predict likely next actions. In practice, MalChain relationships transform isolated events into a coherent timeline of attacker behavior that supports detection, response, and risk assessment.

# INGRESS

**1, Removable Media & File Transfer:**

**Linkage:**

INGRESS → Media Delivery → Trust Establishment → ACTIVATION.

**Relationships:**

- User-Executed Files
- Script-Based Activation
- DLL Side-Loading

**2, Malvertising & Drive-By Downloads:**

**Linkage:**

INGRESS → Web Exposure → Silent Payload Delivery → ACTIVATION.

**Relationships:**

- Script-Based Activation
- User-Executed Files
- DLL Side-Loading

**3, Supply Chain Compromise:**

**Linkage:**

INGRESS → Trusted Update or Dependency → ACTIVATION.

**Relationships:**

- Service-Based Execution
- DLL Side-Loading
- Stealthy Persistence

**4, Credential Abuse:**

**Linkage:**

INGRESS → Authenticated Access → ACTIVATION.

**Relationships:**

- Service-Based Execution
- WMI-Based Execution
- Cloud Resource Abuse

**5, Malicious or Compromised USB Devices:**

**Linkage:**

**Relationships:**

- Script-Based Activation
- User-Executed Files
- Credential Abuse

**6, Watering Hole Attacks:**

**Linkage:**

INGRESS → Targeted Web Exposure → ACTIVATION.

**Relationships:**

- Script-Based Activation
- Credential Abuse
- DLL Side-Loading

**7, External Remote Services:**

**Linkage:**

INGRESS → Authenticated Remote Access → ACTIVATION.

**Relationships:**

- Service-Based Execution
- Credential Abuse
- Lateral Movement

