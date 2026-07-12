# MalChain

> Behaviour-centric malware kill-chain framework — six phases, 52 techniques, each mapped to ready-to-run KQL and YARA detections.

MalChain is an open-source, behaviour-centric malware analysis and detection framework that models real-world adversary operations across the full intrusion lifecycle. Unlike indicator-driven or tool-centric models, it focuses on attacker capabilities, trust abuse, and operational chaining.

## Contents

- [Framework Overview](docs/OVERVIEW.md) — purpose, scope, and how to use it
- [Chain Linking](docs/LINKING.md) — how each phase enables the next
- [Detection Library](docs/DETECTIONS.md) — KQL + YARA coverage matrix
- [About](ABOUT.md) — the project and Malwarehunts

## The kill chain

| Phase | Techniques | Focus |
|-------|-----------|-------|
| [Ingress](docs/phases/ing.md) | 7 | How malware enters systems |
| [Activation](docs/phases/act.md) | 7 | Running malicious code |
| [Anchoring](docs/phases/anc.md) | 8 | Maintaining presence |
| [Concealment](docs/phases/con.md) | 10 | Avoiding detection |
| [Expansion](docs/phases/exp.md) | 10 | Spreading within networks |
| [Extraction](docs/phases/ext.md) | 10 | Stealing data |
| **Total** | **52** | Full intrusion lifecycle |

## Detections

Every technique includes a Microsoft Defender / Sentinel **KQL** query; 30 also include a validated **YARA** rule. See the [Detection Library](docs/DETECTIONS.md) or the phase-grouped rule files under [`detections/`](detections/).

## License

MIT — see [LICENSE.md](LICENSE.md).

**Maintained by [Malwarehunts](https://malwarehunts.com).**
