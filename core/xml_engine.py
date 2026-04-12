"""XML sanitization and CVE extraction engine for Vulnix."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
import re
from typing import Any

from bs4 import BeautifulSoup
from lxml import etree

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# ── Prompt-injection sanitization ─────────────────────────────────────────
# Strip common LLM-manipulation patterns from text that will flow into prompts.
_INJECTION_RE = re.compile(
    r"(ignore\s+(previous|above|prior)\s+instructions?|"
    r"you\s+are\s+now|act\s+as|pretend\s+(you\s+are|to\s+be)|"
    r"disregard\s+(all|any|your)|forget\s+(everything|all)|"
    r"system\s*:|\[INST\]|<\|im_start\|>)",
    re.IGNORECASE,
)

def _sanitize_for_prompt(text: str, max_chars: int = 2000) -> str:
    """
    Truncate and strip potential prompt-injection patterns from
    free-text fields before they are processed by the frontend.
    """
    if not text:
        return ""
    cleaned = _INJECTION_RE.sub("[REDACTED]", text)
    return cleaned[:max_chars]


@dataclass
class XMLProcessingResult:
    raw_xml: str
    cleaned_xml: str
    records: list[dict[str, Any]]
    cve_records: list[dict[str, Any]]
    finding_records: list[dict[str, Any]]
    fixed_error_count: int


class XMLSanitizationError(Exception):
    pass


def _decode_bytes(raw_bytes: bytes) -> str:
    if not raw_bytes:
        raise XMLSanitizationError("Uploaded file is empty.")
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _repair_with_bs4(raw_xml: str) -> str:
    soup = BeautifulSoup(raw_xml, "xml")
    repaired = str(soup)
    if not repaired.strip():
        raise XMLSanitizationError("Failed to repair XML content.")
    return repaired


def _normalize_severity(score: float | None) -> str:
    if score is None:    return "UNKNOWN"
    if score >= 9.0:     return "CRITICAL"
    if score >= 7.0:     return "HIGH"
    if score >= 4.0:     return "MEDIUM"
    if score > 0.0:      return "LOW"
    return "UNKNOWN"


def _safe_float(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except (TypeError, ValueError):
        return None


def _severity_from_text(value: str) -> str:
    """Map arbitrary severity labels to supported values."""
    v = (value or "").upper()
    if "CRITICAL" in v: return "CRITICAL"
    if "HIGH"     in v: return "HIGH"
    if "MEDIUM"   in v: return "MEDIUM"
    if "LOW"      in v: return "LOW"
    return "UNKNOWN"


def _first(node: etree._Element, xpaths: list[str]) -> str:
    for xp in xpaths:
        for item in node.xpath(xp):
            val = (item.text if isinstance(item, etree._Element) else str(item)).strip()
            if val:
                return val
    return ""


def _parse_date(value: str) -> str:
    if not value:
        return ""
    for candidate in (value, value.replace("Z", "+00:00"), value.split("T")[0]):
        try:
            return datetime.fromisoformat(candidate).date().isoformat()
        except ValueError:
            continue
    return value


def _map_owasp_top10(*texts: str) -> str:
    combined = " ".join((t or "") for t in texts).lower()
    if not combined:
        return ""

    ref_match = re.search(r"\bA(0[1-9]|10)_?2021\b", combined, flags=re.IGNORECASE)
    if ref_match:
        return f"A{ref_match.group(1)}"

    keyword_map = [
        ("A01", ("access control", "idor", "insecure direct object", "authorization bypass")),
        ("A02", ("cryptographic", "encryption", "cipher", "tls", "ssl", "hash")),
        ("A03", ("injection", "xss", "sql injection", "command injection", "xxe")),
        ("A04", ("insecure design", "threat model", "business logic")),
        ("A05", ("security misconfiguration", "cors", "header missing", "directory listing", "cache-control")),
        ("A06", ("vulnerable and outdated", "outdated component", "vulnerable js library", "dependency")),
        ("A07", ("authentication", "credential", "brute force", "session fixation", "csrf token")),
        ("A08", ("software and data integrity", "deserialization", "supply chain", "integrity")),
        ("A09", ("logging", "monitoring", "audit trail", "insufficient logging")),
        ("A10", ("ssrf", "server-side request forgery")),
    ]
    for code, keywords in keyword_map:
        if any(k in combined for k in keywords):
            return code
    return ""


def _extract_cve_records(root: etree._Element) -> list[dict[str, Any]]:
    nodes = root.xpath(
        "//*[local-name()='entry' or local-name()='item' or "
        "local-name()='Vulnerability' or local-name()='cve' or local-name()='vuln']"
    )
    records, seen = [], set()
    for node in nodes:
        cve_id = _first(node, [
            ".//*[local-name()='cve-id']/text()", ".//*[local-name()='name']/text()",
            ".//*[local-name()='ID']/text()",     ".//*[local-name()='id']/text()",
            "@id", "@name",
        ])
        if not cve_id.upper().startswith("CVE-") or cve_id in seen:
            continue
        seen.add(cve_id)

        score = _safe_float(_first(node, [
            ".//*[local-name()='cvss3' or local-name()='baseScore']/text()",
            ".//*[local-name()='cvss']/text()", ".//*[local-name()='score']/text()",
        ]))
        severity = _first(node, [
            ".//*[local-name()='baseSeverity']/text()",
            ".//*[local-name()='severity']/text()",
        ]).upper()
        if severity not in SEVERITY_ORDER:
            severity = _normalize_severity(score)

        raw_description = _first(node, [
            ".//*[local-name()='summary']/text()",
            ".//*[local-name()='description']/text()",
            ".//*[local-name()='Description']/text()",
            ".//*[local-name()='desc']/text()",
        ])

        records.append({
            "cve_id":         cve_id,
            "severity":       severity,
            "cvss_score":     score,
            "published_date": _parse_date(_first(node, [
                ".//*[local-name()='published']/text()",
                ".//*[local-name()='publishedDate']/text()",
                ".//*[local-name()='date']/text()",
            ])),
            # Sanitized for safe embedding in AI prompts
            "description": _sanitize_for_prompt(raw_description),
            "cwe": _first(node, [
                ".//*[local-name()='cwe']/text()",
                ".//*[local-name()='CWE']/text()",
            ]),
            "owasp_top10": _map_owasp_top10(
                raw_description,
                _first(node, [".//*[local-name()='cwe']/text()", ".//*[local-name()='CWE']/text()"]),
            ),
        })

    # OWASP ZAP XML support: CVEs are often embedded in alert details.
    zap_alerts = root.xpath("//*[local-name()='alertitem']")
    for idx, node in enumerate(zap_alerts, start=1):
        text_blobs = [
            _first(node, [".//*[local-name()='otherinfo']/text()"]),
            _first(node, [".//*[local-name()='reference']/text()"]),
            _first(node, [".//*[local-name()='desc']/text()"]),
            _first(node, [".//*[local-name()='name']/text()"]),
        ]
        combined = "\n".join(part for part in text_blobs if part)
        cve_ids = {m.group(0).upper() for m in CVE_PATTERN.finditer(combined)}

        severity = _severity_from_text(_first(node, [
            ".//*[local-name()='riskdesc']/text()",
            ".//*[local-name()='risk']/text()",
            ".//*[local-name()='riskcode']/text()",
        ]))
        raw_description = _first(node, [
            ".//*[local-name()='desc']/text()",
            ".//*[local-name()='otherinfo']/text()",
        ])
        description = _sanitize_for_prompt(raw_description)
        alert_name = _first(node, [
            ".//*[local-name()='name']/text()",
            ".//*[local-name()='alert']/text()",
        ])
        cwe_value = _first(node, [
            ".//*[local-name()='cweid']/text()",
            ".//*[local-name()='cwe']/text()",
        ])
        if cwe_value and cwe_value.isdigit():
            cwe_value = f"CWE-{cwe_value}"
        owasp_top10 = _map_owasp_top10(alert_name, raw_description, combined, cwe_value)

        if not cve_ids:
            base_id = _first(node, [
                ".//*[local-name()='pluginid']/text()",
                ".//*[local-name()='alertRef']/text()",
            ]) or str(idx)
            synthetic_id = f"ZAP-{base_id}"
            suffix = 2
            while synthetic_id in seen:
                synthetic_id = f"ZAP-{base_id}-{suffix}"
                suffix += 1
            seen.add(synthetic_id)
            records.append({
                "cve_id":         synthetic_id,
                "severity":       severity,
                "cvss_score":     None,
                "published_date": "",
                "description":    description or _sanitize_for_prompt(alert_name),
                "cwe":            cwe_value,
                "owasp_top10":    owasp_top10,
            })
            continue

        for cve_id in sorted(cve_ids):
            if cve_id in seen:
                continue
            seen.add(cve_id)
            records.append({
                "cve_id":         cve_id,
                "severity":       severity,
                "cvss_score":     None,
                "published_date": "",
                "description":    description or _sanitize_for_prompt(alert_name),
                "cwe":            cwe_value,
                "owasp_top10":    owasp_top10,
            })

    # Generic fallback: capture CVE identifiers appearing anywhere in XML text.
    xml_text = etree.tostring(root, encoding="unicode")
    for match in CVE_PATTERN.finditer(xml_text):
        cve_id = match.group(0).upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        records.append({
            "cve_id":         cve_id,
            "severity":       "UNKNOWN",
            "cvss_score":     None,
            "published_date": "",
            "description":    "",
            "cwe":            "",
            "owasp_top10":    "",
        })
    return records


def _extract_finding_records(root: etree._Element) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    zap_alerts = root.xpath("//*[local-name()='alertitem']")
    if not zap_alerts:
        return findings

    for aidx, node in enumerate(zap_alerts, start=1):
        alert_name = _first(node, [
            ".//*[local-name()='name']/text()",
            ".//*[local-name()='alert']/text()",
        ]) or f"Alert {aidx}"
        raw_description = _first(node, [
            ".//*[local-name()='otherinfo']/text()",
            ".//*[local-name()='desc']/text()",
        ]) or alert_name
        description = _sanitize_for_prompt(raw_description)
        reference = _first(node, [".//*[local-name()='reference']/text()"])
        severity = _severity_from_text(_first(node, [
            ".//*[local-name()='riskdesc']/text()",
            ".//*[local-name()='risk']/text()",
            ".//*[local-name()='riskcode']/text()",
        ]))
        cwe_value = _first(node, [
            ".//*[local-name()='cweid']/text()",
            ".//*[local-name()='cwe']/text()",
        ])
        if cwe_value and cwe_value.isdigit():
            cwe_value = f"CWE-{cwe_value}"

        combined = "\n".join([alert_name, raw_description, reference, cwe_value])
        cves = [m.group(0).upper() for m in CVE_PATTERN.finditer(combined)]
        primary_id = cves[0] if cves else (
            _first(node, [
                ".//*[local-name()='pluginid']/text()",
                ".//*[local-name()='alertRef']/text()",
            ]) or str(aidx)
        )
        owasp_top10 = _map_owasp_top10(alert_name, raw_description, reference, cwe_value)

        instances = node.xpath(".//*[local-name()='instance']")
        if instances:
            for iidx, inst in enumerate(instances, start=1):
                uri = _first(inst, [".//*[local-name()='uri']/text()", ".//*[local-name()='url']/text()"])
                evidence = _first(inst, [".//*[local-name()='evidence']/text()"])
                findings.append({
                    "cve_id":         f"{primary_id}-F{iidx}",
                    "severity":       severity,
                    "cvss_score":     None,
                    "published_date": "",
                    "description":    description,
                    "cwe":            cwe_value,
                    "owasp_top10":    owasp_top10,
                    "uri":            uri,
                    "alert_name":     alert_name,
                    "evidence":       evidence,
                })
            continue

        count = int(_safe_float(_first(node, [".//*[local-name()='count']/text()"])) or 1)
        for iidx in range(1, max(count, 1) + 1):
            findings.append({
                "cve_id":         f"{primary_id}-F{iidx}",
                "severity":       severity,
                "cvss_score":     None,
                "published_date": "",
                "description":    description,
                "cwe":            cwe_value,
                "owasp_top10":    owasp_top10,
                "uri":            "",
                "alert_name":     alert_name,
                "evidence":       "",
            })
    return findings


def sanitize_and_extract(xml_bytes: bytes) -> XMLProcessingResult:
    raw_xml  = _decode_bytes(xml_bytes)
    repaired = _repair_with_bs4(raw_xml)

    # Security: disable entity resolution and network access to prevent XXE
    parser = etree.XMLParser(
        recover=True,
        remove_blank_text=True,
        resolve_entities=False,   # prevents entity expansion attacks
        no_network=True,          # prevents external entity fetching (SSRF)
        load_dtd=False,           # prevents DTD-based attacks
    )
    try:
        root = etree.parse(BytesIO(repaired.encode("utf-8")), parser).getroot()
    except etree.XMLSyntaxError as e:
        raise XMLSanitizationError("Unable to parse XML after repair.") from e

    cleaned = etree.tostring(
        root, pretty_print=True, encoding="utf-8", xml_declaration=True
    ).decode("utf-8")
    cve_records     = _extract_cve_records(root)
    finding_records = _extract_finding_records(root)
    return XMLProcessingResult(
        raw_xml=raw_xml,
        cleaned_xml=cleaned,
        records=cve_records,
        cve_records=cve_records,
        finding_records=finding_records,
        fixed_error_count=len(parser.error_log),
    )
