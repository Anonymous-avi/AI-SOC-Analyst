from app.schemas.security_alert import AlertSeverity, SecurityAlert


def _format_value(value: str | int | float | None) -> str:
    if value is None:
        return "Unavailable"

    if isinstance(value, str):
        cleaned_value = value.strip()
        return cleaned_value if cleaned_value else "Unavailable"

    return str(value)


def _format_list(values: list[str]) -> list[str]:
    return [value for value in values if value and value.strip()]


def _append_section(
    lines: list[str],
    title: str,
    body_lines: list[str],
) -> None:
    lines.append(title)
    lines.append("----------------")
    lines.extend(body_lines)
    lines.append("")


def generate_ai_summary(alert: SecurityAlert) -> str:
    lines: list[str] = ["🤖 AI SECURITY INVESTIGATION REPORT", ""]

    attack_overview = (
        f"This alert indicates a {_format_value(alert.attack_type)} incident. "
        f"The activity was observed with {_format_value(alert.risk_level)} risk, "
        f"a {_format_value(alert.severity)} severity rating, and "
        f"{_format_value(alert.confidence)} confidence."
    )

    if alert.attacker_ip:
        attack_overview += f" The likely source IP is {alert.attacker_ip}."

    _append_section(lines, "Attack Overview", [attack_overview])

    _append_section(
        lines,
        "Risk Assessment",
        [
            f"Threat Score: {_format_value(alert.threat_score)}",
            f"Risk Level: {_format_value(alert.risk_level)}",
            f"Severity: {_format_value(alert.severity)}",
            f"Confidence: {_format_value(alert.confidence)}",
        ],
    )

    _append_section(
        lines,
        "MITRE ATT&CK Mapping",
        [
            f"Tactic: {_format_value(alert.mitre.tactic)}",
            f"Technique: {_format_value(alert.mitre.technique)}",
            f"Technique ID: {_format_value(alert.mitre.technique_id)}",
        ],
    )

    indicator_lines: list[str] = []

    if alert.attacker_ip:
        indicator_lines.append(f"Attacker IP: {alert.attacker_ip}")

    if alert.iocs.ips:
        ips = _format_list(alert.iocs.ips)
        if ips:
            indicator_lines.append(f"IPs: {', '.join(ips)}")

    if alert.iocs.hashes:
        hashes = _format_list(alert.iocs.hashes)
        if hashes:
            indicator_lines.append(f"Hashes: {', '.join(hashes)}")

    if alert.iocs.domains:
        domains = _format_list(alert.iocs.domains)
        if domains:
            indicator_lines.append(f"Domains: {', '.join(domains)}")

    if alert.iocs.urls:
        urls = _format_list(alert.iocs.urls)
        if urls:
            indicator_lines.append(f"URLs: {', '.join(urls)}")

    if alert.iocs.malware:
        malware = _format_list(alert.iocs.malware)
        if malware:
            indicator_lines.append(f"Malware: {', '.join(malware)}")

    if alert.iocs.cves:
        cves = _format_list(alert.iocs.cves)
        if cves:
            indicator_lines.append(f"CVEs: {', '.join(cves)}")

    if alert.iocs.emails:
        emails = _format_list(alert.iocs.emails)
        if emails:
            indicator_lines.append(f"Emails: {', '.join(emails)}")

    if not indicator_lines:
        indicator_lines.append("No indicators of compromise were identified.")

    _append_section(lines, "Indicators of Compromise", indicator_lines)

    _append_section(
        lines,
        "Business Impact",
        [
            "If this attack succeeds, it could lead to unauthorized access, "
            "service disruption, credential compromise, data exposure, or a "
            "broader intrusion depending on the exposed asset and blast radius.",
        ],
    )

    recommended_actions: list[str] = []

    if alert.attacker_ip:
        recommended_actions.append(f"Block attacker IP {alert.attacker_ip}.")

    if alert.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}:
        recommended_actions.append(
            "Escalate the alert to the SOC incident response process."
        )

    if alert.attack_type:
        recommended_actions.append(
            f"Review systems affected by the {alert.attack_type.lower()} activity."
        )

    recommended_actions.extend(
        [
            "Reset affected credentials if compromise is suspected.",
            "Enable or enforce MFA for exposed accounts.",
            "Monitor authentication, process, and network logs for follow-up activity.",
        ]
    )

    _append_section(
        lines,
        "Recommended Actions",
        [
            f"{index}. {action}"
            for index, action in enumerate(recommended_actions, start=1)
        ],
    )

    _append_section(
        lines,
        "Conclusion",
        [
            f"The alert is consistent with a {_format_value(alert.attack_type).lower()}-type incident "
            f"that warrants analyst review and containment. Prioritize the exposed assets, confirm "
            f"whether the observed indicators are benign or malicious, and validate that the recommended "
            f"controls are in place.",
        ],
    )

    return "\n".join(lines).rstrip()