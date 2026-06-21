"""
Cross-framework compliance mapping engine.

Maps control failures across regulatory frameworks to identify coverage overlaps
and gaps. A single failed control in one framework may implicate multiple controls
across other frameworks, providing a unified compliance posture view.
"""
from typing import Dict, List, Optional

# Cross-framework control mapping database
# Maps a source framework category_id to equivalent controls in other frameworks
CROSS_FRAMEWORK_MAP: Dict[str, List[Dict[str, str]]] = {
    # ---- SENTINEL Default Schema ----
    "CAT_DATA_HANDLING": [
        {"framework": "SOC 2", "control": "CC6.1 — Logical and Physical Access Controls", "tsc": "Security"},
        {"framework": "ISO 27001", "control": "A.8.10 — Information Deletion", "annex": "A.8"},
        {"framework": "NIST CSF", "control": "PR.DS-1 — Data-at-rest is protected", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 3 — Protect Stored Account Data", "requirement": "3"},
    ],
    "CAT_ACCESS_CONTROLS": [
        {"framework": "SOC 2", "control": "CC6.1 — Logical Access Security", "tsc": "Security"},
        {"framework": "ISO 27001", "control": "A.8.3 — Access restriction (Privileged)", "annex": "A.8"},
        {"framework": "NIST CSF", "control": "PR.AC-1 — Identities and credentials issued", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 7 — Restrict Access by Business Need", "requirement": "7"},
    ],
    "CAT_INCIDENT_RESPONSE": [
        {"framework": "SOC 2", "control": "CC7.3 — Evaluate Security Events", "tsc": "Security"},
        {"framework": "ISO 27001", "control": "A.5.24 — Information Security Incident Management", "annex": "A.5"},
        {"framework": "NIST CSF", "control": "RS.AN-1 — Notifications from detection systems investigated", "function": "Respond"},
        {"framework": "PCI-DSS v4.0", "control": "Req 12.10 — Respond to Security Incidents", "requirement": "12"},
    ],
    "CAT_BUSINESS_CONTINUITY": [
        {"framework": "SOC 2", "control": "A1.2 — Recovery from disruptions", "tsc": "Availability"},
        {"framework": "ISO 27001", "control": "A.5.30 — ICT Readiness for Business Continuity", "annex": "A.5"},
        {"framework": "NIST CSF", "control": "RC.RP-1 — Recovery plan is executed", "function": "Recover"},
        {"framework": "PCI-DSS v4.0", "control": "Req 12.10.2 — Incident Response Plan", "requirement": "12"},
    ],
    "CAT_ENCRYPTION": [
        {"framework": "SOC 2", "control": "CC6.1 — Encryption of Data in Transit", "tsc": "Security"},
        {"framework": "ISO 27001", "control": "A.8.24 — Use of Cryptography", "annex": "A.8"},
        {"framework": "NIST CSF", "control": "PR.DS-2 — Data-in-transit is protected", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 4 — Encrypt Transmission of Cardholder Data", "requirement": "4"},
    ],
    # ---- SOC 2 Schema ----
    "CAT_SOC2_SECURITY": [
        {"framework": "ISO 27001", "control": "A.8.3 — Privileged Access Restriction", "annex": "A.8"},
        {"framework": "NIST CSF", "control": "PR.AC-1 — Credentials and Access Management", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 1-2 — Network Security Controls", "requirement": "1"},
    ],
    "CAT_SOC2_AVAILABILITY": [
        {"framework": "ISO 27001", "control": "A.5.30 — ICT Readiness for Business Continuity", "annex": "A.5"},
        {"framework": "NIST CSF", "control": "RC.RP-1 — Recovery Plan Executed", "function": "Recover"},
    ],
    "CAT_SOC2_CONFIDENTIALITY": [
        {"framework": "ISO 27001", "control": "A.8.10 — Information Deletion", "annex": "A.8"},
        {"framework": "NIST CSF", "control": "PR.DS-1 — Data-at-rest Protected", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 3 — Protect Stored Account Data", "requirement": "3"},
    ],
    # ---- ISO 27001 Schema ----
    "CAT_ISO_ORGANIZATIONAL": [
        {"framework": "SOC 2", "control": "CC1.1 — Organizational Structure", "tsc": "Common Criteria"},
        {"framework": "NIST CSF", "control": "ID.GV-1 — Cybersecurity Policy Established", "function": "Identify"},
    ],
    "CAT_ISO_PEOPLE": [
        {"framework": "SOC 2", "control": "CC1.4 — Attracts and Retains Competent Individuals", "tsc": "Common Criteria"},
        {"framework": "NIST CSF", "control": "PR.AT-1 — Security Awareness Training", "function": "Protect"},
    ],
    "CAT_ISO_PHYSICAL": [
        {"framework": "SOC 2", "control": "CC6.4 — Physical Access Restrictions", "tsc": "Security"},
        {"framework": "PCI-DSS v4.0", "control": "Req 9 — Physical Access Restriction", "requirement": "9"},
    ],
    "CAT_ISO_TECHNICAL": [
        {"framework": "SOC 2", "control": "CC6.1 — Logical Access Security", "tsc": "Security"},
        {"framework": "NIST CSF", "control": "PR.AC-4 — Access Permissions Managed", "function": "Protect"},
        {"framework": "PCI-DSS v4.0", "control": "Req 7 — Restrict Access by Business Need", "requirement": "7"},
    ],
    # ---- NIST CSF Schema ----
    "CAT_NIST_IDENTIFY": [
        {"framework": "ISO 27001", "control": "A.5.1 — Policies for Information Security", "annex": "A.5"},
        {"framework": "SOC 2", "control": "CC1.1 — COSO Principle 1", "tsc": "Common Criteria"},
    ],
    "CAT_NIST_PROTECT": [
        {"framework": "ISO 27001", "control": "A.8.3 — Access Restriction", "annex": "A.8"},
        {"framework": "SOC 2", "control": "CC6.1 — Logical Access", "tsc": "Security"},
        {"framework": "PCI-DSS v4.0", "control": "Req 7 — Access Restriction", "requirement": "7"},
    ],
    "CAT_NIST_DETECT": [
        {"framework": "ISO 27001", "control": "A.8.16 — Monitoring Activities", "annex": "A.8"},
        {"framework": "SOC 2", "control": "CC7.2 — Monitor System Components", "tsc": "Security"},
        {"framework": "PCI-DSS v4.0", "control": "Req 10 — Log and Monitor All Access", "requirement": "10"},
    ],
    "CAT_NIST_RESPOND": [
        {"framework": "ISO 27001", "control": "A.5.24 — Incident Management Planning", "annex": "A.5"},
        {"framework": "SOC 2", "control": "CC7.3 — Evaluate Security Events", "tsc": "Security"},
    ],
    "CAT_NIST_RECOVER": [
        {"framework": "ISO 27001", "control": "A.5.30 — ICT Business Continuity", "annex": "A.5"},
        {"framework": "SOC 2", "control": "A1.2 — Recovery from Disruptions", "tsc": "Availability"},
    ],
    # ---- PCI-DSS Schema ----
    "CAT_PCI_NETWORK": [
        {"framework": "SOC 2", "control": "CC6.6 — Security Measures for External Threats", "tsc": "Security"},
        {"framework": "NIST CSF", "control": "PR.AC-5 — Network Integrity Protected", "function": "Protect"},
        {"framework": "ISO 27001", "control": "A.8.20 — Network Security", "annex": "A.8"},
    ],
    "CAT_PCI_DATA_PROT": [
        {"framework": "SOC 2", "control": "CC6.1 — Encryption of Data", "tsc": "Security"},
        {"framework": "NIST CSF", "control": "PR.DS-1 / PR.DS-2 — Data Protection", "function": "Protect"},
        {"framework": "ISO 27001", "control": "A.8.24 — Use of Cryptography", "annex": "A.8"},
    ],
    "CAT_PCI_VULN_MGMT": [
        {"framework": "SOC 2", "control": "CC7.1 — Detect and Respond to Changes", "tsc": "Security"},
        {"framework": "NIST CSF", "control": "DE.CM-8 — Vulnerability Scans Performed", "function": "Detect"},
        {"framework": "ISO 27001", "control": "A.8.8 — Management of Technical Vulnerabilities", "annex": "A.8"},
    ],
    "CAT_PCI_ACCESS_CTRL": [
        {"framework": "SOC 2", "control": "CC6.1 — Logical Access", "tsc": "Security"},
        {"framework": "NIST CSF", "control": "PR.AC-1 — Identity and Access Management", "function": "Protect"},
        {"framework": "ISO 27001", "control": "A.8.3 — Access Restriction", "annex": "A.8"},
    ],
}


class ComplianceMapper:
    """
    Maps failed control categories to equivalent controls across regulatory frameworks.
    This enables a single assessment to surface compliance exposure across SOC 2,
    ISO 27001, NIST CSF 2.0, and PCI-DSS v4.0 simultaneously.
    """

    def map_failed_categories(self, failed_category_ids: List[str]) -> Dict[str, List[Dict[str, str]]]:
        """
        Given a list of failed category IDs, return a dictionary keyed by
        framework name containing all implicated controls.
        """
        result: Dict[str, List[Dict[str, str]]] = {}
        seen: Dict[str, set] = {}

        for cat_id in failed_category_ids:
            mappings = CROSS_FRAMEWORK_MAP.get(cat_id, [])
            for mapping in mappings:
                fw = mapping["framework"]
                ctrl = mapping["control"]
                if fw not in result:
                    result[fw] = []
                    seen[fw] = set()
                if ctrl not in seen[fw]:
                    seen[fw].add(ctrl)
                    result[fw].append(mapping)

        return result

    def get_compliance_coverage_score(self, failed_category_ids: List[str], total_categories: int) -> Dict[str, float]:
        """
        Calculate compliance coverage percentage per framework.
        A higher score means better compliance; a lower score means more failures.
        """
        if total_categories == 0:
            return {}

        mapped = self.map_failed_categories(failed_category_ids)
        failed_fraction = len(failed_category_ids) / total_categories
        
        scores = {}
        for fw, controls in mapped.items():
            # More implicated controls = lower compliance score for that framework
            impact_factor = min(1.0, len(controls) / 5.0)
            compliance_score = max(0.0, (1.0 - (failed_fraction * impact_factor)) * 100.0)
            scores[fw] = round(compliance_score, 1)

        return scores

    def generate_unified_report(self, failed_category_ids: List[str], total_categories: int) -> Dict:
        """
        Generate a complete cross-framework compliance report.
        """
        mapped = self.map_failed_categories(failed_category_ids)
        coverage = self.get_compliance_coverage_score(failed_category_ids, total_categories)
        
        total_implicated = sum(len(ctrls) for ctrls in mapped.values())

        return {
            "total_frameworks_impacted": len(mapped),
            "total_controls_implicated": total_implicated,
            "framework_coverage_scores": coverage,
            "framework_details": {
                fw: {
                    "implicated_controls": controls,
                    "coverage_score": coverage.get(fw, 100.0)
                }
                for fw, controls in mapped.items()
            }
        }
