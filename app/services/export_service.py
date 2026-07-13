import io
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def export_markdown(content: str) -> bytes:
    return content.encode("utf-8")


def export_pdf(markdown_content: str, ioc_value: str) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        story = []

        title_style = ParagraphStyle("title", parent=styles["Heading1"], fontSize=16, spaceAfter=12)
        body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=10, spaceAfter=6, leading=14)

        story.append(Paragraph(f"ThreatChain Report: {ioc_value}", title_style))
        story.append(Spacer(1, 0.3*cm))

        for line in markdown_content.split("\n"):
            if line.startswith("# "):
                story.append(Paragraph(line[2:], styles["Heading1"]))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], styles["Heading2"]))
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], styles["Heading3"]))
            elif line.strip():
                safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                story.append(Paragraph(safe, body_style))
            else:
                story.append(Spacer(1, 0.2*cm))

        doc.build(story)
        return buf.getvalue()
    except Exception as e:
        logger.error("PDF export failed: %s", e)
        return markdown_content.encode("utf-8")


def _sanitize_stix_value(value: str) -> str:
    """Escape single quotes in IOC values to prevent STIX pattern injection."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


_HASH_ALGO_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _hash_pattern(safe_value: str) -> str:
    """Build a file hash pattern, detecting the algorithm by length.

    stix2 validates hash values against the declared algorithm, so a
    hardcoded SHA-256 pattern rejects MD5 and SHA-1 IOCs. Values that do
    not look like a known hash fall back to a file name match so the
    export still produces a valid bundle instead of failing.
    """
    is_hex = all(c in "0123456789abcdefABCDEF" for c in safe_value)
    algo = _HASH_ALGO_BY_LENGTH.get(len(safe_value)) if is_hex else None
    if algo:
        return f"[file:hashes.'{algo}' = '{safe_value}']"
    return f"[file:name = '{safe_value}']"


def export_stix(
    ioc_value: str,
    ioc_type: str,
    investigation_id: str,
    verdict: str,
    mitre_techniques: list,
    related_iocs: list,
) -> bytes:
    try:
        import stix2

        safe_value = _sanitize_stix_value(ioc_value)

        pattern_map = {
            "ip": f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{safe_value}']",
            "domain": f"[domain-name:value = '{safe_value}']",
            "hash": _hash_pattern(safe_value),
            "url": f"[url:value = '{safe_value}']",
            "email": f"[email-addr:value = '{safe_value}']",
        }

        pattern = pattern_map.get(ioc_type, f"[domain-name:value = '{safe_value}']")
        labels = ["malicious-activity"] if verdict == "malicious" else ["suspicious-activity"]

        indicator = stix2.Indicator(
            name=f"ThreatChain: {ioc_value}",
            description=f"Investigated IOC: {ioc_value} (type: {ioc_type}). Verdict: {verdict}.",
            pattern=pattern,
            pattern_type="stix",
            labels=labels,
            valid_from=datetime.now(timezone.utc),
        )

        objects = [indicator]

        for tech in mitre_techniques[:5]:
            tid = tech.get("technique_id", "")
            tname = tech.get("technique_name", "")
            if tid:
                ap = stix2.AttackPattern(
                    name=f"{tid} - {tname}",
                    description=tech.get("evidence", ""),
                    external_references=[
                        stix2.ExternalReference(
                            source_name="mitre-attack",
                            external_id=tid,
                            url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                        )
                    ],
                )
                objects.append(ap)
                rel = stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=ap.id,
                )
                objects.append(rel)

        bundle = stix2.Bundle(objects=objects)
        return bundle.serialize(pretty=True).encode("utf-8")

    except Exception as e:
        # Propagate instead of returning an error payload: callers must not
        # serve a broken bundle as if the export had succeeded.
        logger.error("STIX export failed for investigation %s: %s", investigation_id, e)
        raise
