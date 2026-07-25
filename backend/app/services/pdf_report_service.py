from io import BytesIO
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)

styles = getSampleStyleSheet()


def heading(text):
    style = styles["Heading2"]
    style.textColor = colors.HexColor("#0F62FE")
    return Paragraph(text, style)


def body(text):
    return Paragraph(text, styles["BodyText"])


def generate_pdf_report(alert: dict, ai_summary: str):

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    story = []

    story.append(Paragraph(
        "<b>AI SOC ANALYST INCIDENT REPORT</b>",
        styles["Title"],
    ))

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y %H:%M')}",
            styles["Italic"],
        )
    )

    story.append(Spacer(1, 20))

    # -------------------------------------------------

    story.append(heading("Alert Information"))

    story.append(body(
        f"""
        <b>Alert ID:</b> {alert.get('alert_id')}<br/>
        <b>Attack Type:</b> {alert.get('attack_type')}<br/>
        <b>Severity:</b> {alert.get('severity')}<br/>
        <b>Risk Level:</b> {alert.get('risk_level')}<br/>
        <b>Threat Score:</b> {alert.get('threat_score')}<br/>
        <b>Confidence:</b> {round(alert.get('confidence',0)*100)}%
        """
    ))

    story.append(Spacer(1, 15))

    # -------------------------------------------------

    mitre = alert.get("mitre", {})

    story.append(heading("MITRE ATT&CK"))

    story.append(body(
        f"""
        <b>Tactic:</b> {mitre.get('tactic','N/A')}<br/>
        <b>Technique:</b> {mitre.get('technique','N/A')}<br/>
        <b>Technique ID:</b> {mitre.get('technique_id','N/A')}
        """
    ))

    story.append(Spacer(1, 15))

    # -------------------------------------------------

    iocs = alert.get("iocs", {})

    story.append(heading("Indicators of Compromise"))

    for key, values in iocs.items():

        if values:

            value = ", ".join(values)

            story.append(body(
                f"<b>{key.title()}:</b> {value}"
            ))

    story.append(Spacer(1, 15))

    # -------------------------------------------------

    intel = alert.get("threat_intelligence", [])

    story.append(heading("Threat Intelligence"))

    if intel:

        for item in intel:

            story.append(body(
                f"""
                <b>Indicator:</b> {item.get('indicator')}<br/>
                <b>Provider:</b> {item.get('provider')}<br/>
                <b>Reputation:</b> {item.get('reputation')}
                """
            ))

            story.append(Spacer(1, 5))

    else:

        story.append(body("No threat intelligence available."))

    story.append(Spacer(1, 15))

    # -------------------------------------------------

    story.append(heading("AI Investigation Report"))

    story.append(body(ai_summary.replace("\n", "<br/>")))

    story.append(Spacer(1, 15))

    # -------------------------------------------------

    story.append(heading("Recommendations"))

    recommendation = alert.get(
        "recommendation",
        "No recommendation available.",
    )

    story.append(body(recommendation))

    doc.build(story)

    buffer.seek(0)

    return buffer