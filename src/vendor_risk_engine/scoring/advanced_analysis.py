"""
Advanced GRC Analysis: MITRE ATT&CK Mapping, FAIR Quantitative Risk Modeling,
Remediation Tracker with SLA Enforcement, and Trend Analysis.
"""
import csv
from pathlib import Path
from datetime import date, datetime, timezone, timedelta
from typing import List, Dict, Optional
from vendor_risk_engine.models.score import VendorScore, CategoryScore
from vendor_risk_engine.models.response import ValidatedResponse

# MITRE ATT&CK category mapping database
MITRE_ATTACK_MAP = {
    "CAT_DATA_HANDLING": [
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "severity": "HIGH"},
        {"technique_id": "T1537", "name": "Transfer Data to Cloud Account", "tactic": "Exfiltration", "severity": "MEDIUM"}
    ],
    "CAT_ACCESS_CONTROLS": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion, Persistence, Privilege Escalation", "severity": "CRITICAL"},
        {"technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "HIGH"}
    ],
    "CAT_INCIDENT_RESPONSE": [
        {"technique_id": "T1614", "name": "System Location Discovery", "tactic": "Discovery", "severity": "LOW"},
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "CRITICAL"}
    ],
    "CAT_BUSINESS_CONTINUITY": [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "CRITICAL"},
        {"technique_id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "severity": "CRITICAL"}
    ],
    "CAT_ENCRYPTION": [
        {"technique_id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access, Discovery", "severity": "HIGH"},
        {"technique_id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access, Collection", "severity": "HIGH"}
    ],
    "CAT_SOC2_SECURITY": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "severity": "CRITICAL"},
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "CRITICAL"}
    ],
    "CAT_SOC2_AVAILABILITY": [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "CRITICAL"}
    ],
    "CAT_SOC2_CONFIDENTIALITY": [
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "severity": "CRITICAL"}
    ],
    "CAT_ISO_ORGANIZATIONAL": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Persistence", "severity": "MEDIUM"}
    ],
    "CAT_ISO_PEOPLE": [
        {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access", "severity": "HIGH"}
    ],
    "CAT_ISO_PHYSICAL": [
        {"technique_id": "T1091", "name": "Replication Through Removable Media", "tactic": "Initial Access", "severity": "LOW"}
    ],
    "CAT_ISO_TECHNICAL": [
        {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "severity": "HIGH"}
    ],
    "CAT_NIST_IDENTIFY": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "severity": "MEDIUM"}
    ],
    "CAT_NIST_PROTECT": [
        {"technique_id": "T1565", "name": "Data Manipulation", "tactic": "Impact", "severity": "HIGH"}
    ],
    "CAT_NIST_DETECT": [
        {"technique_id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion", "severity": "HIGH"}
    ],
    "CAT_NIST_RESPOND": [
        {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "severity": "CRITICAL"}
    ],
    "CAT_NIST_RECOVER": [
        {"technique_id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "severity": "CRITICAL"}
    ],
    "CAT_PCI_NETWORK": [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "CRITICAL"}
    ],
    "CAT_PCI_DATA_PROT": [
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "severity": "CRITICAL"}
    ],
    "CAT_PCI_VULN_MGMT": [
        {"technique_id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "severity": "HIGH"}
    ],
    "CAT_PCI_ACCESS_CTRL": [
        {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Credential Access", "severity": "CRITICAL"}
    ]
}

class AdvancedGRCAnalyzer:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def map_mitre_gaps(self, failed_categories: List[str]) -> List[Dict]:
        """Map failed questionnaire categories to MITRE ATT&CK techniques."""
        mapped = []
        seen = set()
        for cat_id in failed_categories:
            if cat_id in MITRE_ATTACK_MAP:
                for tech in MITRE_ATTACK_MAP[cat_id]:
                    key = tech["technique_id"]
                    if key not in seen:
                        seen.add(key)
                        mapped.append(tech)
        return mapped

    def calculate_fair_risk(self, tier: str, score: float) -> Dict:
        """FAIR-aligned quantitative risk modeling based on risk tier and total score."""
        # Baseline Annualized Rate of Occurrence (ARO)
        if tier == "High":
            aro = 1.5
        elif tier == "Medium":
            aro = 0.5
        else:
            aro = 0.1

        # Single Loss Expectancy (SLE) baseline
        base_sle = 250000.0
        # Scale SLE based on security score (lower score = higher damage exposure)
        sle = base_sle * (1.0 + (100.0 - score) / 100.0)
        
        # Annual Loss Expectancy (ALE)
        ale = aro * sle
        
        # Residual Risk Value (RRV) assuming some organizational mitigation mitigates 30% further
        rrv = ale * 0.70

        return {
            "annualized_rate_of_occurrence": round(aro, 2),
            "single_loss_expectancy_usd": round(sle, 2),
            "annual_loss_expectancy_usd": round(ale, 2),
            "residual_risk_value_usd": round(rrv, 2)
        }

    def generate_remediation_tickets(self, score: VendorScore, response: ValidatedResponse) -> List[Dict]:
        """Generate remediation tickets with SLA enforcement for failed items."""
        # Find failed questions (gaps) from the gap list or response values
        tickets = []
        
        # Determine SLA based on tier
        if score.classification_tier == "High":
            sla_days = 30
        elif score.classification_tier == "Medium":
            sla_days = 60
        else:
            sla_days = 90
            
        due_date = (date.today() + timedelta(days=sla_days)).isoformat()
        
        # Parse gap strings (question_id: recommendation)
        for gap_str in response.gap_list:
            if ":" in gap_str:
                q_id, rec = gap_str.split(":", 1)
                q_id = q_id.strip()
                rec = rec.strip()
                
                # Check if critical
                is_crit = q_id.endswith("01") or "CRIT" in q_id or score.classification_tier == "High"
                
                tickets.append({
                    "ticket_id": f"REM-{score.vendor_id}-{q_id}-{uuid_prefix()}",
                    "vendor_id": score.vendor_id,
                    "vendor_name": score.vendor_name,
                    "question_id": q_id,
                    "sla_days": sla_days,
                    "due_date": due_date,
                    "assigned_owner": "Vendor Compliance Officer",
                    "action_required": f"Provide evidence for: {rec}",
                    "priority": "CRITICAL" if is_crit else "HIGH" if score.classification_tier == "High" else "MEDIUM",
                    "status": "OPEN"
                })
        return tickets

    def analyze_trends(self, vendor_id: str, current_score: float, current_gaps: int) -> Dict:
        """Analyze score delta and velocity across historical assessment runs."""
        csv_path = self.output_dir / "assessment_results.csv"
        if not csv_path.exists():
            return {
                "previous_score": None,
                "score_delta": 0.0,
                "previous_gaps": None,
                "gap_delta": 0,
                "velocity_status": "STABLE (No History)"
            }

        previous_score = None
        previous_gaps = None
        
        try:
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row["vendor_id"] == vendor_id:
                        previous_score = float(row["total_score"])
                        previous_gaps = int(row.get("gap_unanswered_count", 0))
        except Exception:
            pass

        if previous_score is None:
            return {
                "previous_score": None,
                "score_delta": 0.0,
                "previous_gaps": None,
                "gap_delta": 0,
                "velocity_status": "STABLE (First Run)"
            }

        score_delta = current_score - previous_score
        gap_delta = current_gaps - previous_gaps

        if score_delta > 0.0:
            velocity = "IMPROVING"
        elif score_delta < 0.0:
            velocity = "DEGRADED"
        else:
            velocity = "STABLE"

        return {
            "previous_score": previous_score,
            "score_delta": round(score_delta, 2),
            "previous_gaps": previous_gaps,
            "gap_delta": gap_delta,
            "velocity_status": velocity
        }

def uuid_prefix() -> str:
    import uuid
    return uuid.uuid4().hex[:6].upper()
