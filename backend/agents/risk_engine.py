"""
backend/agents/risk_engine.py
------------------------------
Risk-Weighted Autonomy Engine for Chimera SOC.

Computes a normalized risk score from triage confidence, blast radius, and
asset criticality, then decides whether the SOC can auto-mitigate or must
escalate to a human analyst.
"""


def compute_incident_risk(
    confidence: float,
    blast_radius_hosts: int = 1,
    asset_criticality: float = 0.8,
) -> dict:
    """
    Compute a normalized incident risk score and determine the autonomous action.

    Formula:
        risk = min(1.0, confidence * (blast_radius_hosts * 0.4) * asset_criticality)

    Decision thresholds:
        risk <  0.4  → auto-mitigate via n8n firewall block (no human needed)
        risk >= 0.4  → stage for human analyst approval

    Args:
        confidence:          Triage confidence score (0.0–1.0).
        blast_radius_hosts:  Estimated number of hosts potentially affected (default 1).
        asset_criticality:   Criticality rating of the affected asset (0.0–1.0, default 0.8).

    Returns:
        dict: {
            "risk_score":        float,   # 0.0–1.0 normalized score
            "autonomous_action": bool,    # True  → SOC acts without human
            "status":            str,     # "auto_mitigated" | "staged_for_human"
            "action":            str,     # recommended playbook action
        }
    """
    risk_score = min(1.0, confidence * (blast_radius_hosts * 0.4) * asset_criticality)

    if risk_score < 0.4:
        return {
            "risk_score": round(risk_score, 4),
            "autonomous_action": True,
            "status": "auto_mitigated",
            "action": "n8n_firewall_block",
        }
    else:
        return {
            "risk_score": round(risk_score, 4),
            "autonomous_action": False,
            "status": "staged_for_human",
            "action": "require_analyst_approval",
        }
