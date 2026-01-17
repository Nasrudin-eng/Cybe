# Cybe
AI-Native Cyber Threat Correlation Prototype that shows how fragmented security alerts can be linked into unified incidents. The engine correlates identity, cloud, and endpoint signals using shared entities like users, devices, and IPs to reconstruct attack chains, generate incident narratives, assign scores, and recommend response actions.

## Deployment model
Cybe is intended to run as an intelligence layer inside an existing security stack. A typical deployment looks like:

1. **Ingestion**: Security events flow in from SIEM, EDR, IAM, and cloud logs.
2. **Normalization + correlation**: Events are normalized, correlated, and enriched into incidents.
3. **Operational outputs**: Incidents emit recommended actions, timelines, evidence, and optional sharing exports.
4. **Downstream systems**: SOAR, ticketing, or dashboards consume the incident output.

The prototype is implemented as a Python module today but can be wrapped behind an API or worker.

## Competitive positioning
Cybe complements SIEM/XDR/SOAR platforms by providing:
- Deterministic, explainable correlation
- Incident-level intelligence with risk, confidence, and evidence
- Secure sharing with clearance enforcement and tokenization

## Pricing model (guidance)
Typical commercial models to consider:
- **Usage-based**: events/day or incidents/day
- **Tenant-based**: per-tenant monthly license
- **Integration-based**: pricing tiers by number of connectors enabled

The appropriate model depends on data volume, SLA requirements, and integration depth.
