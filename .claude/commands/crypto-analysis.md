---
description: "Trace cryptographic configuration and ownership across application, container, and platform layers."
---

Run a crypto governance analysis using the crypto-analysis skill. Load the skill at harnessing/3-audit/crypto-analysis/SKILL.md and follow its full procedure — collect crypto facts using python3 -m traust.cli adapters crypto-source|crypto-image|crypto-cluster (source, image, and/or cluster tiers as appropriate for the target), build governance chains tracing crypto ownership from OS platform through container to application code, resolve each chain's crypto_impact and ownership, and feed pqc-readiness when PQC assessment is needed. Target is $ARGUMENTS (repository path, image reference, or cluster context). This skill is the sole orchestrator of crypto census invocations — other skills delegate crypto depth here.
