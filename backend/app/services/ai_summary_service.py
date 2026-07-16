from app.schemas.security_alert import SecurityAlert


def generate_ai_summary(alert: SecurityAlert) -> str:

    summary = (
        f"This alert indicates a "
        f"{alert.attack_type} attack.\n\n"

        f"The attacker IP "
        f"{alert.attacker_ip or 'Unknown'} "
        f"generated an event with "
        f"{alert.risk_level} risk and a "
        f"threat score of "
        f"{alert.threat_score}.\n\n"

        f"This activity maps to "
        f"MITRE ATT&CK technique "
        f"{alert.mitre.technique_id} "
        f"({alert.mitre.technique}).\n\n"

        f"Recommended action:\n"
        f"{alert.recommendation}"
    )

    return summary