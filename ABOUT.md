# About MalChain

**MalChain** is an open-source, behaviour-centric malware kill-chain framework maintained by [Malwarehunts](https://malwarehunts.com). It models real-world adversary operations across the full intrusion lifecycle by abstracting attacker actions into reusable operational capabilities that stay stable even as malware tooling evolves.

## Who maintains it

MalChain is a project by [Malwarehunts](https://malwarehunts.com) — a threat-research effort focused on malware analysis, detection engineering, and threat hunting. The goal is to help defenders reason about attacker behaviour in a structured, high-fidelity way and turn that understanding into detections they can deploy the same day.

## Who it's for

Security operations centres, detection-engineering and threat-hunting teams, incident responders, malware researchers, and red / purple teams. MalChain is platform-agnostic and applies across endpoint, network, cloud, and hybrid environments.

## What's inside

Six phases — Ingress, Activation, Anchoring, Concealment, Expansion, and Extraction — covering 52 techniques. Each technique carries a summary, detection guidance, a ready-to-run Microsoft Defender / Sentinel KQL query, a YARA rule where file or memory artifacts apply, mitigation and incident-response notes, and chain-linking to the techniques it enables next.

## Contributing

Contributions are welcome — malware case studies, new or tuned detection signatures (KQL and YARA), and technical analysis. Open an issue or pull request on [GitHub](https://github.com/Malwarehunts/Malchain).

## Stay in touch

Read more research and analysis at [malwarehunts.com](https://malwarehunts.com), or follow development on [GitHub](https://github.com/Malwarehunts/Malchain).
